#pragma once
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <filesystem>
#include <system_error>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <hsma/params.hpp>
#include <hsma/fe.hpp>
#include <hsma/poseidon.hpp>

namespace hsma::smt {

inline constexpr std::size_t ENTRY_BYTES = 64;
inline constexpr std::size_t SEG_SLOTS   = 1 << 18;
inline constexpr std::size_t SEG_BYTES   = SEG_SLOTS * ENTRY_BYTES;
static_assert(SEG_BYTES % 4096 == 0);

enum class Tag : std::uint8_t { MID = 1, TLEAF = 2, REC = 3 };
using Handle = std::uint64_t;
inline constexpr Handle HEMPTY = 0;

constexpr Handle mk_handle(std::uint64_t seg, std::uint64_t slot, Tag t) noexcept {
    return (std::uint64_t(t) << 58) | (seg << 42) | slot;
}
constexpr Tag         h_tag (Handle h) noexcept { return Tag(h >> 58); }
constexpr std::uint64_t h_seg (Handle h) noexcept { return (h >> 42) & 0xFFFF; }
constexpr std::uint64_t h_slot(Handle h) noexcept { return h & ((1ULL << 42) - 1); }

#pragma pack(push, 1)
struct Entry { std::uint8_t tag; std::uint8_t pad[7]; std::uint64_t w[7]; };
static_assert(sizeof(Entry) == 64);

struct ControlSector {
    std::uint8_t  magic[8];
    std::uint32_t fmt_version;
    std::uint32_t n_segments;
    std::uint64_t params_fingerprint;
    std::uint64_t tail_slot;
    std::uint64_t roots[48];
    std::uint32_t n_roots;
    std::uint8_t  reserved[512 - 8 - 4 - 4 - 8 - 8 - 384 - 4];
};
static_assert(sizeof(ControlSector) == 512);
#pragma pack(pop)

class Vault {
public:
    Vault() = default;
    ~Vault() { close(); }
    Vault(const Vault&) = delete;
    Vault& operator=(const Vault&) = delete;

    bool open(const std::string& dir) {
        dir_ = dir;
        std::error_code ec;
        std::filesystem::create_directories(dir_, ec);
        if (ec) {
            fail(("mkdir failed: " + ec.message()).c_str());
            return false;
        }
        if (!open_control()) return false;
        for (std::uint32_t s = 0; s < ctls_.n_segments; ++s)
            if (!map_segment(s)) return false;
        build_empty_table();
        return true;
    }

    Handle latest_root() const noexcept {
        return ctls_.n_roots ? ctls_.roots[ctls_.n_roots - 1] : HEMPTY;
    }
    bool fork_epoch(Handle new_root) { return commit_control(new_root); }

    const Entry* deref(Handle h) const noexcept {
        if (h == HEMPTY) return nullptr;
        return reinterpret_cast<const Entry*>(segs_[h_seg(h)].base
                                              + h_slot(h) * ENTRY_BYTES);
    }
    const std::array<fp::fe, params::SMT_DEPTH + 1>& empty_table() const noexcept {
        return empty_;
    }

    static fp::fe entry_hash(const Entry& e) noexcept {
        fp::fe f{};
        const std::uint64_t* src = (e.tag == std::uint8_t(Tag::MID))   ? e.w + 2
                                 : (e.tag == std::uint8_t(Tag::TLEAF)) ? e.w + 1
                                                                       : e.w;
        std::memcpy(f.l.data(), src, 32);
        return f;
    }
    static void store_fe(Entry& e, int at, const fp::fe& f) noexcept {
        std::memcpy(e.w + at, f.l.data(), 32);
    }

    std::string last_error() const { return err_; }

protected:
    friend class Updater;
    friend class Prover;
    struct Seg { std::uint8_t* base = nullptr; int fd = -1; };

    void close() noexcept {
        for (auto& s : segs_) if (s.base) ::munmap(s.base, SEG_BYTES);
        if (ctl_fd_ >= 0) ::close(ctl_fd_);
    }
    void fail(const std::string& m) { err_ = m; }

    bool open_control() {
        const auto path = dir_ + "/control.bin";
        const bool fresh = ::access(path.c_str(), F_OK) != 0;
        ctl_fd_ = ::open(path.c_str(), O_RDWR | O_CREAT, 0644);
        if (ctl_fd_ < 0) {
            fail("control open: " + std::string(std::strerror(errno)));
            return false;
        }
        if (fresh) {
            ControlSector c{};
            std::memcpy(c.magic, "HSMSMT\1\0", 8);
            c.fmt_version        = 1;
            c.params_fingerprint = params::PARAMS_FINGERPRINT;
            c.n_segments         = 1;
            if (::pwrite(ctl_fd_, &c, sizeof c, 0) != (ssize_t)sizeof c || ::fsync(ctl_fd_) != 0) {
                fail("control init: " + std::string(std::strerror(errno)));
                return false;
            }
        }
        if (::pread(ctl_fd_, &ctls_, sizeof ctls_, 0) != sizeof ctls_) {
            fail("control read: " + std::string(std::strerror(errno)));
            return false;
        }
        if (std::memcmp(ctls_.magic, "HSMSMT\1\0", 8) != 0)
            { fail("not an HSMA vault"); return false; }
        if (ctls_.params_fingerprint != params::PARAMS_FINGERPRINT)
            { fail("params fingerprint mismatch"); return false; }
        tail_slot_ = ctls_.tail_slot;
        segs_.resize(ctls_.n_segments);
        return true;
    }

    bool write_control(const ControlSector& c) {
        const auto tmp = dir_ + "/control.tmp";
        int fd = ::open(tmp.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) return false;
        const bool ok = ::pwrite(fd, &c, sizeof c, 0) == (ssize_t)sizeof c
                     && ::fsync(fd) == 0;
        ::close(fd);
        return ok && ::rename(tmp.c_str(), (dir_ + "/control.bin").c_str()) == 0;
    }
    bool commit_control(Handle new_root) {
        if (ctls_.n_roots < 48) ctls_.roots[ctls_.n_roots++] = new_root;
        else {
            for (std::size_t i = 1; i < 48; ++i) ctls_.roots[i-1] = ctls_.roots[i];
            ctls_.roots[47] = new_root;
        }
        ctls_.tail_slot = tail_slot_;
        return write_control(ctls_);
    }

    void build_empty_table() {
        empty_[0] = fp::poseidon3(dom::Dom::IV_STATE_LEAF, fp::fe_zero(), fp::fe_zero());
        for (std::size_t h = 0; h < params::SMT_DEPTH; ++h)
            empty_[h + 1] = fp::poseidon3(dom::Dom::IV_STATE_NODE,
                                          empty_[h], empty_[h]);
    }

    bool map_segment(std::uint32_t idx) {
        char name[64];
        std::snprintf(name, sizeof name, "/seg%05u.bin", idx);
        const auto path = dir_ + name;
        int fd = ::open(path.c_str(), O_RDWR | O_CREAT, 0644);
        if (fd < 0) {
            fail("segment open: " + std::string(std::strerror(errno)));
            return false;
        }
        struct stat st{};
        ::fstat(fd, &st);
        if (st.st_size < (off_t)SEG_BYTES && ::ftruncate(fd, SEG_BYTES) != 0) {
            fail("ftruncate: " + std::string(std::strerror(errno)));
            ::close(fd);
            return false;
        }
#ifdef HAVE_FALLOCATE
        if (::fallocate(fd, 0, 0, SEG_BYTES) != 0) {}
#endif
        void* m = ::mmap(nullptr, SEG_BYTES, PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_NORESERVE, fd, 0);
        if (m == MAP_FAILED) {
            fail("mmap: " + std::string(std::strerror(errno)));
            ::close(fd);
            return false;
        }
        ::madvise(m, SEG_BYTES, MADV_HUGEPAGE);
        if (idx >= segs_.size()) segs_.resize(idx + 1);
        segs_[idx] = Seg{reinterpret_cast<std::uint8_t*>(m), fd};
        return true;
    }

    Handle alloc(const Entry& e) {
        if (segs_.empty() || tail_slot_ >= SEG_SLOTS) {
            const auto idx = std::uint32_t(segs_.size());
            if (!map_segment(idx)) return HEMPTY;
            ctls_.n_segments = idx + 1;
        }
        const Handle h = mk_handle(std::uint64_t(segs_.size() - 1), tail_slot_,
                                   Tag(e.tag));
        std::memcpy(segs_.back().base + tail_slot_ * ENTRY_BYTES, &e, ENTRY_BYTES);
        ++tail_slot_;
        return h;
    }

    std::string   dir_;
    int           ctl_fd_ = -1;
    ControlSector ctls_{};
    std::vector<Seg> segs_;
    std::uint64_t tail_slot_ = 0;
    std::array<fp::fe, params::SMT_DEPTH + 1> empty_{};
    std::string   err_;
};

} // namespace hsma::smt
