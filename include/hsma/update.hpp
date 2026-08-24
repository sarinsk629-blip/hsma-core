// HSMA :: update.hpp — CoW updates · proofs · verifier
// DEC-112 leaf binding · DEC-113 elision · DEC-123 canonical keys at rest
// DEC-126 slot schema: payload = 126|1|64|1 = 192 bits (exact 24-B window)
// DEC-127 init law: aggregates only ({}) — never memset after member assign
#pragma once
#include <cstring>
#include <hsma/vault.hpp>

namespace hsma::smt {

struct AccountState {
    unsigned __int128 bal_mag;      // < 2^126
    bool bal_sign;
    std::uint64_t nonce;
    std::uint8_t  flags;            // 1-bit register (E-6)
};

inline bool encode_payload_bytes(const AccountState& s, std::byte buf[32]) noexcept {
    constexpr unsigned __int128 BAL_CAP = (((unsigned __int128)1) << 126);
    if (s.bal_sign && s.bal_mag == 0) return false;
    if (s.bal_mag >= BAL_CAP)         return false;
    if (s.flags > 1)                  return false;
    std::memset(buf, 0, 32);
    auto put = [](std::byte* b, unsigned __int128 v, int lo, int bits) {
        for (int i = 0; i < bits; ++i)
            if ((v >> i) & 1)
                reinterpret_cast<std::uint8_t*>(b)[(lo + i) >> 3] |=
                    std::uint8_t(1 << ((lo + i) & 7));
    };
    put(buf, s.bal_mag, 0, 126);
    put(buf, s.bal_sign ? 1 : 0, 126, 1);
    put(buf, s.nonce, 127, 64);
    put(buf, s.flags, 191, 1);
    return true;
}
inline fp::fe pack_payload(const AccountState& s, bool* ok) noexcept {
    std::byte b[32];
    *ok = encode_payload_bytes(s, b);
    if (!*ok) return fp::fe_zero();
    return fp::fe_from_le_bytes(b).value;
}
inline AccountState unpack_payload(const fp::fe& packed) noexcept {
    const fp::fe c = fp::fe_to_canonical(packed);
    const auto* p = reinterpret_cast<const std::uint8_t*>(c.l.data());
    auto get = [&](int lo, int bits) {
        unsigned __int128 acc = 0;
        for (int i = bits - 1; i >= 0; --i)
            acc = (acc << 1) | ((p[(lo + i) >> 3] >> ((lo + i) & 7)) & 1);
        return acc;
    };
    AccountState s{};
    s.bal_mag  = get(0, 126);
    s.bal_sign = get(126, 1) != 0;
    s.nonce    = std::uint64_t(get(127, 64));
    s.flags    = std::uint8_t(get(191, 1));
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
        if (!encode_payload_bytes(st, buf)) { res.stats.noop = true; return res; }
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
            spine[lvl].sib_hash = sib ? Vault::entry_hash(*v_.deref(sib))
                                      : v_.empty_table()[std::size_t(lvl)];
            cur = bit ? rc : lc;
        }

        if (cur != HEMPTY) {                       // collision guard + no-op
            const Entry* tl = v_.deref(cur);
            const Entry* rc = v_.deref(tl->w[0]);
            fp::fe sk{};
            std::memcpy(sk.l.data(), rc->w, 32);
            if (!(sk == fp::fe_to_canonical(key))) {       // stored = canonical
                res.stats.fault = true; return res;
            }
            bool same_payload = true;
            for (int i = 0; i < 24 && same_payload; ++i)
                same_payload =
                    (reinterpret_cast<const std::uint8_t*>(rc->w + 4)[i]
                     == reinterpret_cast<const std::uint8_t*>(buf)[i]);
            if (same_payload && Vault::entry_hash(*tl) == new_leaf) {
                res.stats.noop = true;                     // zero writes
                return res;
            }
        }

        const fp::fe ck = fp::fe_to_canonical(key);        // DEC-123
        Entry rec{};                                       // DEC-127: {} only
        rec.tag = std::uint8_t(Tag::REC);
        std::memcpy(rec.w,     ck.l.data(), 32);
        std::memcpy(rec.w + 4, buf,         24);           // exact window
        const Handle rh = v_.alloc(rec);  ++res.stats.rec;

        Entry tl{};                                        // DEC-127
        tl.tag = std::uint8_t(Tag::TLEAF);
        tl.w[0] = rh; Vault::store_fe(tl, 1, new_leaf);
        Handle child = v_.alloc(tl);      ++res.stats.tleaf;
        fp::fe child_hash = new_leaf;

        const Handle orig_root = root;
        for (int lvl = 0; lvl < int(params::SMT_DEPTH); ++lvl) {
            const Row&  sr  = spine[lvl];
            const bool  bit = (idx >> lvl) & 1;
            if (child == HEMPTY && sr.sib == HEMPTY) {
                ++res.stats.wedges_elided;
                child_hash = v_.empty_table()[std::size_t(lvl)]; // E[lvl]: python-parity height
                continue;
            }
            const fp::fe cand = bit
                ? fp::poseidon3(dom::Dom::IV_STATE_NODE, sr.sib_hash, child_hash)
                : fp::poseidon3(dom::Dom::IV_STATE_NODE, child_hash, sr.sib_hash);
            if (sr.mid != HEMPTY &&
                Vault::entry_hash(*v_.deref(sr.mid)) == cand) {
                ++res.stats.short_circuits;
                res.root_unchanged = true;
                res.new_root = orig_root;
                return res;
            }
            Entry mid{};                                   // DEC-127
            mid.tag = std::uint8_t(Tag::MID);
            mid.w[0] = bit ? sr.sib : child;
            mid.w[1] = bit ? child   : sr.sib;
            Vault::store_fe(mid, 2, cand);
            child = v_.alloc(mid); child_hash = cand; ++res.stats.mid;
        }
        res.new_root = child;
        return res;
    }

private:
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
        if (p.occupied)
            std::memcpy(p.leaf_hash.l.data(), v_.deref(cur)->w + 1, 32);
        return p;
    }
private:
    Vault& v_;
};

// CONTRACT (DEC-134, supersedes DEC-133): expected_root is a RAW DIGEST —
// canonical limbs passed as uint64_t[4]. Roots NEVER travel as fe; there is
// no Montgomery/canonical ambiguity possible at this boundary.
inline bool verify_opening(const std::uint64_t expected_root[4],
                           const fp::fe& key,
                           const AccountState* st, const OpeningProof& pr) {
    fp::fe acc;
    if (pr.occupied != (st != nullptr)) return false;
    if (st) {
        std::byte buf[32];
        if (!encode_payload_bytes(*st, buf)) return false;
        acc = fp::poseidon3(dom::Dom::IV_STATE_LEAF, key,
                            fp::fe_from_le_bytes(buf).value);
        if (!(acc == pr.leaf_hash)) return false;
    } else {
        acc = pr.leaf_hash;
    }
    const std::uint64_t idx = index_of(key);
    for (int lvl = 0; lvl < int(params::SMT_DEPTH); ++lvl)
        acc = ((idx >> lvl) & 1)
            ? fp::poseidon3(dom::Dom::IV_STATE_NODE, pr.sib[lvl], acc)
            : fp::poseidon3(dom::Dom::IV_STATE_NODE, acc, pr.sib[lvl]);
    return std::memcmp(fp::fe_to_canonical(acc).l.data(),
                       expected_root, 32) == 0;
}

} // namespace hsma::smt
