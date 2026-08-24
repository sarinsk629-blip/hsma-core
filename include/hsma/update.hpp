#pragma once
#include <hsma/vault.hpp>

namespace hsma::smt {

struct AccountState {
    unsigned __int128 bal_mag;
    bool bal_sign;
    std::uint64_t nonce;
    std::uint8_t  flags;
};

inline bool encode_payload_bytes(const AccountState& s, std::byte buf[32]) noexcept {
    if ((s.bal_sign && s.bal_mag == 0) || (s.bal_mag >= ((unsigned __int128)1 << 120)) || (s.nonce >= (1ULL << 63)))
        return false;
    std::memset(buf, 0, 32);
    auto put = [](std::byte* b, unsigned __int128 v, int lo, int bits) {
        for (int i = 0; i < bits; ++i)
            if ((v >> i) & 1)
                reinterpret_cast<std::uint8_t*>(b)[(lo + i) >> 3] |=
                    std::uint8_t(1 << ((lo + i) & 7));
    };
    put(buf, s.bal_mag, 0, 120);
    put(buf, s.bal_sign ? 1 : 0, 120, 1);
    put(buf, s.nonce, 121, 63);
    put(buf, s.flags, 184, 8);
    return true;
}

inline fp::fe pack_payload(const AccountState& s, bool* ok) noexcept {
    std::byte buf[32];
    *ok = encode_payload_bytes(s, buf);
    if (!*ok) return fp::fe_zero();
    return fp::fe_from_le_bytes(buf).value;
}

inline AccountState unpack_payload(const fp::fe& packed) noexcept {
    const fp::fe c = fp::fe_to_canonical(packed);
    const auto* b = reinterpret_cast<const std::uint8_t*>(c.l.data());
    auto get = [&](int lo, int bits) {
        unsigned __int128 acc = 0;
        for (int i = bits - 1; i >= 0; --i)
            acc = (acc << 1) | ((b[(lo + i) >> 3] >> ((lo + i) & 7)) & 1);
        return acc;
    };
    AccountState s{};
    s.bal_mag  = get(0, 120);
    s.bal_sign = get(120, 1) != 0;
    s.nonce    = std::uint64_t(get(121, 63));
    s.flags    = std::uint8_t(get(184, 8));
    return s;
}

inline fp::fe key_from_pk(const fp::fe& lo, const fp::fe& hi) noexcept {
    return fp::poseidon3(dom::Dom::IV_IDENT, lo, hi);
}

inline std::uint64_t index_of(const fp::fe& key) noexcept {
    return fp::fe_to_canonical(key).l[0];
}

struct UpdateStats {
    std::uint64_t rec = 0, tleaf = 0, mid = 0;
    std::uint32_t wedges_elided = 0, short_circuits = 0;
    bool noop = false, fault = false;
    std::uint64_t total() const noexcept { return rec + tleaf + mid; }
};

struct UpdateResult { Handle new_root = 0; bool root_unchanged = false; UpdateStats stats; };

class Updater {
public:
    explicit Updater(Vault& v) : v_(v) {}

    UpdateResult set_account(Handle root, const fp::fe& key, const AccountState& st) {
        UpdateResult res{root, false, {}};
        std::byte buf[32];
        bool ok = encode_payload_bytes(st, buf);
        if (!ok) { res.stats.noop = true; return res; }
        const fp::fe packed = fp::fe_from_le_bytes(buf).value;

        const std::uint64_t idx = index_of(key);
        const fp::fe new_leaf =
            fp::poseidon3(dom::Dom::IV_STATE_LEAF, key, packed);

        struct Row { Handle mid = 0, sib = 0; fp::fe sib_hash{}; };
        Row spine[params::SMT_DEPTH];
        Handle cur = root;
        for (int lvl = int(params::SMT_DEPTH) - 1; lvl >= 0; --lvl) {
            const bool bit = (idx >> lvl) & 1;
            if (cur == HEMPTY) {
                spine[lvl].sib_hash = v_.empty_table()[std::size_t(lvl)];
                continue;
            }
            const Entry* e = v_.deref(cur);
            const Handle lc = e->w[0], rc = e->w[1];
            const Handle sib = bit ? lc : rc;
            spine[lvl].mid = cur;
            spine[lvl].sib = sib;
            spine[lvl].sib_hash = sib ? entry_h(*v_.deref(sib))
                                      : v_.empty_table()[std::size_t(lvl)];
            cur = bit ? rc : lc;
        }

        bool occupied = cur != HEMPTY;
        if (occupied) {
            const Entry* tl = v_.deref(cur);
            const Entry* rc = v_.deref(tl->w[0]);
            fp::fe sk{};
            std::memcpy(sk.l.data(), rc->w, 32);

            std::byte rbuf[32];
            std::memset(rbuf, 0, 32);
            std::memcpy(rbuf, rc->w + 4, 24);
            const fp::fe sp = fp::fe_from_le_bytes(rbuf).value;

            if (!(sk == key)) {
                res.stats.fault = true; return res;
            }
            if (sp == packed &&
                Vault::entry_hash(*tl) == new_leaf) {
                res.stats.noop = true;
                return res;
            }
        }

        Entry rec{};  rec.tag = std::uint8_t(Tag::REC);
        std::memset(&rec, 0, sizeof(rec));
        std::memcpy(rec.w,     key.l.data(), 32);
        std::memcpy(rec.w + 4, buf,          24);
        const Handle rh = v_.alloc(rec);  ++res.stats.rec;

        Entry tl{};   tl.tag = std::uint8_t(Tag::TLEAF);
        tl.w[0] = rh; Vault::store_fe(tl, 1, new_leaf);
        Handle child = v_.alloc(tl);      ++res.stats.tleaf;
        fp::fe child_hash = new_leaf;

        for (int lvl = 0; lvl < int(params::SMT_DEPTH); ++lvl) {
            const Row&  sr  = spine[lvl];
            const bool  bit = (idx >> lvl) & 1;
            if (child == HEMPTY && sr.sib == HEMPTY) {
                ++res.stats.wedges_elided;
                child_hash = v_.empty_table()[std::size_t(lvl) + 1];
                continue;
            }
            const fp::fe cand = bit ? fp::poseidon3(dom::Dom::IV_STATE_NODE,
                                                    sr.sib_hash, child_hash)
                                    : fp::poseidon3(dom::Dom::IV_STATE_NODE,
                                                    child_hash, sr.sib_hash);
            Entry mid{}; mid.tag = std::uint8_t(Tag::MID);
            mid.w[0] = bit ? sr.sib : child;
            mid.w[1] = bit ? child   : sr.sib;
            Vault::store_fe(mid, 2, cand);
            child = v_.alloc(mid); child_hash = cand; ++res.stats.mid;
        }
        res.new_root = child;
        return res;
    }

private:
    static fp::fe entry_h(const Entry& e) noexcept { return Vault::entry_hash(e); }
    Vault& v_;
};

struct OpeningProof {
    bool occupied = false;
    fp::fe leaf_hash{};
    fp::fe sib[params::SMT_DEPTH];
};

class Prover {
public:
    explicit Prover(Vault& v) : v_(v) {}
    OpeningProof open(Handle root, const fp::fe& key) const {
        OpeningProof p;
        const std::uint64_t idx = index_of(key);
        Handle cur = root;
        for (int lvl = int(params::SMT_DEPTH) - 1; lvl >= 0; --lvl) {
            const bool bit = (idx >> lvl) & 1;
            if (cur == HEMPTY) {
                for (int q = lvl; q >= 0; --q)
                    p.sib[q] = v_.empty_table()[std::size_t(q)];
                return p;
            }
            const Entry* e = v_.deref(cur);
            const Handle sib = bit ? e->w[0] : e->w[1];
            p.sib[lvl] = sib ? Vault::entry_hash(*v_.deref(sib))
                             : v_.empty_table()[std::size_t(lvl)];
            cur = bit ? e->w[1] : e->w[0];
        }
        p.occupied = cur != HEMPTY;
        if (p.occupied) {
            const Entry* tl = v_.deref(cur);
            std::memcpy(p.leaf_hash.l.data(), tl->w + 1, 32);
        }
        return p;
    }
private:
    Vault& v_;
};

inline bool verify_opening(const fp::fe& expected_root, const fp::fe& key,
                           const AccountState* st, const OpeningProof& p) {
    fp::fe acc;
    if (p.occupied != (st != nullptr)) return false;
    if (st) {
        std::byte buf[32];
        bool ok = encode_payload_bytes(*st, buf);
        if (!ok) return false;
        const fp::fe packed = fp::fe_from_le_bytes(buf).value;
        acc = fp::poseidon3(dom::Dom::IV_STATE_LEAF, key, packed);
        if (!(acc == p.leaf_hash)) return false;
    } else {
        acc = p.leaf_hash;
    }
    const std::uint64_t idx = index_of(key);
    for (int lvl = 0; lvl < int(params::SMT_DEPTH); ++lvl) {
        acc = ((idx >> lvl) & 1)
            ? fp::poseidon3(dom::Dom::IV_STATE_NODE, p.sib[lvl], acc)
            : fp::poseidon3(dom::Dom::IV_STATE_NODE, acc, p.sib[lvl]);
    }
    return fp::fe_to_canonical(acc) == fp::fe_to_canonical(expected_root);
}

} // namespace hsma::smt
