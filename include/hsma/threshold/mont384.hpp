// HSMA :: threshold/mont384.hpp — 384-bit Montgomery engine (Step 8, DEC-185)
// VERBATIM promotion of tools/bls_derive.cpp §1–2. The tool remains the
// derivation authority (DEC-109); this module reproduces its outputs under
// golden parity (DEC-187). In-source laws preserved: CANONICALIZATION LAW,
// n0 kernel check, T[i] carry-out form. DEC-127 aggregate-init; DEC-090
// integer-only. Deviations (documented): exp_m2 omitted (never read);
// fe6 r{} normalization in mmul.
#pragma once
#include <array>
#include <cstdint>
#include <cstring>

namespace hsma::threshold::mont {
using u64  = std::uint64_t;
using u128 = unsigned __int128;
using fe6  = std::array<u64, 6>;

inline void bn_cpy(u64* d, const u64* s, int n){ for(int i=0;i<n;++i) d[i]=s[i]; }
inline void bn_clr(u64* d, int n){ for(int i=0;i<n;++i) d[i]=0; }
inline bool bn_isz(const u64* a, int n){ for(int i=0;i<n;++i) if(a[i]) return false; return true; }
inline int  bn_cmp(const u64* a, const u64* b, int n){
  for(int i=n-1;i>=0;--i){ if(a[i]!=b[i]) return a[i]<b[i]?-1:1; }
  return 0;
}
inline u64 bn_add(u64* d, const u64* s, int n){
  u64 c=0;
  for(int i=0;i<n;++i){ u128 t=(u128)d[i]+s[i]+c; d[i]=(u64)t; c=(u64)(t>>64); }
  return c;
}
inline u64 bn_sub(u64* d, const u64* s, int n){
  u64 br=0;
  for(int i=0;i<n;++i){ u128 t=(u128)d[i]-s[i]-br; d[i]=(u64)t; br=(u64)((t>>64)&1); }
  return br;
}
inline void bn_shr1(u64* d, int n){
  for(int i=0;i<n-1;++i) d[i]=(d[i]>>1)|(d[i+1]<<63);
  d[n-1]>>=1;
}
inline void bn_mul(const u64* a, int na, const u64* b, int nb, u64* c){
  bn_clr(c, na+nb);
  for(int i=0;i<na;++i){
    u64 cy=0;
    for(int j=0;j<nb;++j){
      u128 t=(u128)c[i+j]+(u128)a[i]*b[j]+cy; c[i+j]=(u64)t; cy=(u64)(t>>64);
    }
    for(int k=i+nb; cy; ++k){ u128 t=(u128)c[k]+cy; c[k]=(u64)t; cy=(u64)(t>>64); }
  }
}
inline u64 bn_divsmall(u64* x, int n, u64 d){
  u64 r=0;
  for(int i=n-1;i>=0;--i){ u128 t=((u128)r<<64)|x[i]; x[i]=(u64)(t/d); r=(u64)(t%d); }
  return r;
}
inline void bn_inc(u64* d, int n){ for(int i=0;i<n;++i){ if(++d[i]) break; } }
// shift-subtract modular oracle — independent truth for conformance vectors
inline void bn_mod(u64* x, int n, const u64* m){
  fe6 r{}; bool hi=false;
  for(int i=n*64-1;i>=0;--i){
    u64 bit=(x[i>>6]>>(i&63))&1ULL;
    u64 c=0;
    for(int k=0;k<6;++k){ u128 t=((u128)r[k]<<1)|(k==0?bit:0)|c; r[k]=(u64)t; c=(u64)(t>>64); }
    hi = hi || (c!=0);
    if(hi || bn_cmp(r.data(),m,6)>=0){ bn_sub(r.data(),m,6); hi=false; }
  }
  bn_cpy(x,r.data(),6);
}

struct MCtx { fe6 m{}; u64 n0=0; fe6 r1{}; fe6 rr{}; };

inline void newton_inv(u64 m0, u64& n0){
  // Newton-Raphson: x <- x(2 - m0*x). Seed x=m0 is correct to 3 bits (m0 odd).
  u64 x = m0;
  for(int i=0;i<5;++i) x *= 2u - m0*x;   // 3->6->12->24->48->96 >= 64 bits
  n0 = ~x + 1ULL;                        // n0 = -m^{-1} mod 2^64 (REDC constant)
}
inline fe6 pow2_mod(const u64* m, int e){
  fe6 v{}; v[0]=1;
  for(int i=0;i<e;++i){
    u64 c=0;
    for(int k=0;k<6;++k){ u128 t=((u128)v[k]<<1)|c; v[k]=(u64)t; c=(u64)(t>>64); }
    if(c || bn_cmp(v.data(),m,6)>=0) bn_sub(v.data(),m,6);
  }
  return v;
}
inline fe6 mmul(const MCtx& C, const fe6& a, const fe6& b){
  u64 T[12]{};
  for(int i=0;i<6;++i){
    u64 cy=0;
    for(int j=0;j<6;++j){
      u128 t=(u128)T[i+j]+(u128)a[j]*b[i]+cy; T[i+j]=(u64)t; cy=(u64)(t>>64);
    }
    T[i+6]+=cy;
  }
  for(int i=0;i<6;++i){
    const u64 mi=T[i]*C.n0;
    u128 cu=(u128)T[i]+(u128)mi*C.m[0];   // T[i] MUST join the carry-out (fe.hpp form)
    u64 cr=(u64)(cu>>64);
    for(int j=1;j<6;++j){
      cu=(u128)T[i+j]+(u128)mi*C.m[j]+cr; T[i+j]=(u64)cu; cr=(u64)(cu>>64);
    }
    cu=(u128)T[i+6]+cr; T[i+6]=(u64)cu; cr=(u64)(cu>>64);
    for(int k=i+7; cr && k<12; ++k){
      cu=(u128)T[k]+cr; T[k]=(u64)cu; cr=(u64)(cu>>64);
    }
  }
  fe6 r{}; std::memcpy(r.data(), T+6, 48);
  if(bn_cmp(r.data(), C.m.data(), 6)>=0) bn_sub(r.data(), C.m.data(), 6);
  return r;
}
inline fe6 madd(const MCtx& C, const fe6& a, const fe6& b){
  fe6 r{}; u64 cy=0;
  for(int i=0;i<6;++i){ u128 s=(u128)a[i]+b[i]+cy; r[i]=(u64)s; cy=(u64)(s>>64); }
  if(cy || bn_cmp(r.data(),C.m.data(),6)>=0) bn_sub(r.data(),C.m.data(),6);
  return r;
}
inline fe6 msub(const MCtx& C, const fe6& a, const fe6& b){
  fe6 r{}; u64 br=0;
  for(int i=0;i<6;++i){ u128 s=(u128)a[i]-b[i]-br; r[i]=(u64)s; br=(u64)((s>>64)&1); }
  if(br){ u64 cy=bn_add(r.data(),C.m.data(),6); (void)cy; }
  return r;
}
inline fe6 mfrom(const MCtx& C, const fe6& canon){ return mmul(C,canon,C.rr); }
inline fe6 mto(const MCtx& C, const fe6& mont){
  // CANONICALIZATION LAW: multiply by RAW 1, never by R.
  //   mul(x*R, 1) = x*R/R = x      <- exit Montgomery domain
  //   mul(x*R, R) = x*R            <- (the old bug) stayed inside it
  fe6 one{}; one[0]=1;
  return mmul(C, mont, one);
}
inline fe6 mpow (const MCtx& C, const fe6& a, const fe6& e){
  fe6 r=C.r1, b=a;
  for(int i=5;i>=0;--i){
    for(int k=63;k>=0;--k){
      r=mmul(C,r,r);
      if((e[i]>>k)&1ULL) r=mmul(C,r,b);
    }
  }
  return r;
}
} // namespace hsma::threshold::mont
