// HSMA :: threshold/g1.hpp — BLS12-377 G1 (Step 8, DEC-185..188)
// VERBATIM promotion of bls_derive.cpp §4 (tonelli) + §7 (Jacobian), plus
// generator/affine helpers. Curve: y^2 = x^3 + 1 (b=1, canonical BLS12-377).
// Coordinates: Jacobian, Montgomery domain. Scalars: canonical fe6 limbs.
// Globals -> initialize-once ctx() (Errata E-4). Line-number tripwires
// dropped (stale in a header); semantic guards retained.
#pragma once
#include <hsma/threshold/mont384.hpp>
#include <bls_q_params_gen.hpp>
#include <cstdio>
#include <cstdlib>

namespace hsma::threshold::g1 {
using mont::fe6; using mont::u64;
using mont::mmul; using mont::madd; using mont::msub; using mont::mfrom;
using mont::mto; using mont::mpow;

struct Ctx {
  mont::MCtx m{};   // mod-q Montgomery context
  fe6 b{};          // b = 1 (Montgomery)
  fe6 halfq{};      // (q-1)/2 canonical
  fe6 m2{};         // q-2 canonical (Fermat inverse exponent)
  fe6 rmod{};       // r canonical (subgroup exponent)
  fe6 h1{};         // cofactor canonical
  fe6 sodd{};       // odd part of q-1 canonical
  fe6 ne{};         // h1*r = #E canonical
  int e = 0;        // 2-adicity of q-1
};

inline const Ctx& ctx(){
  static const Ctx c = []{
    Ctx t{};
    mont::bn_cpy(t.m.m.data(), blsq::Q_MOD, 6);
    mont::newton_inv(blsq::Q_MOD[0], t.m.n0);       // SINGLE SOURCE OF TRUTH
    if(blsq::Q_MOD[0]*t.m.n0 != ~0ULL){ std::fprintf(stderr,"FATAL: n0 kernel\n"); std::abort(); }
    if(t.m.n0 != blsq::Q_N0){ std::fprintf(stderr,"FATAL: n0 != Q_N0\n"); std::abort(); }
    mont::bn_cpy(t.m.r1.data(), blsq::Q_R1, 6);
    mont::bn_cpy(t.m.rr.data(), blsq::Q_R2, 6);
    if(!(t.m.r1 == mont::pow2_mod(blsq::Q_MOD, 384)) ||
       !(t.m.rr == mont::pow2_mod(blsq::Q_MOD, 768))){
      std::fprintf(stderr,"FATAL: R1/R2 mismatch vs pow2_mod\n"); std::abort();
    }
    fe6 bone{}; bone[0]=1;
    t.b = mfrom(t.m, bone);                          // b = 1 (canonical BLS12-377)
    mont::bn_cpy(t.halfq.data(), blsq::Q_HALFQ, 6);
    mont::bn_cpy(t.m2.data(), blsq::Q_M2, 6);
    mont::bn_cpy(t.rmod.data(), blsq::Q_RMOD, 6);
    mont::bn_cpy(t.h1.data(), blsq::Q_H1, 6);
    mont::bn_cpy(t.sodd.data(), blsq::Q_SODD, 6);
    mont::bn_cpy(t.ne.data(), blsq::Q_NE, 6);
    t.e = int(blsq::Q_E);
    return t;
  }();
  return c;   // initialize-once; zero cost thereafter
}

inline fe6 cneg(const fe6& a){
  const mont::MCtx& QC = ctx().m;
  fe6 r{}; mont::bn_cpy(r.data(),QC.m.data(),6);
  u64 br=mont::bn_sub(r.data(),a.data(),6); (void)br;
  return r;
}

inline fe6 tonelli_q(const fe6& a){
  const Ctx& CX = ctx();
  const mont::MCtx& QC = CX.m;
  if(mont::bn_isz(a.data(),6)) return a;
  fe6 one{}; one[0]=1;
  fe6 zc{}; zc[0]=2; fe6 z=zc;
  bool nr=false;
  for(int g=0; g<512 && !nr; ++g){
    fe6 chk = mto(QC, mpow(QC, mfrom(QC,zc), CX.halfq));
    if(!(chk==one)){ z=zc; nr=true; break; }
    mont::bn_inc(zc.data(),6);
  }
  if(!nr){ std::printf("FATAL: no non-residue\n"); std::exit(1); }
  fe6 Ma=mfrom(QC,a);
  fe6 c = mpow(QC, mfrom(QC,z), CX.sodd);
  fe6 t = mpow(QC, Ma, CX.sodd);
  fe6 e2 = CX.sodd;
  { u64 o[6]={1,0,0,0,0,0}; mont::bn_add(e2.data(),o,6); }
  mont::bn_shr1(e2.data(),6);
  fe6 R = mpow(QC, Ma, e2);
  int M = CX.e;
  int guard=0;
  while(!(t==QC.r1)){
    if(++guard > 2*CX.e + 8){
      std::printf("FATAL: tonelli did not converge — kernel defect\n"); std::exit(1);
    }
    int i=0; fe6 t2=t;
    while(!(t2==QC.r1)){ t2=mmul(QC,t2,t2); ++i; }
    if(i>=M){ std::printf("FATAL: tonelli order violation\n"); std::exit(1); }
    fe6 b=c;
    for(int k=0;k<M-i-1;++k) b=mmul(QC,b,b);
    fe6 b2=mmul(QC,b,b);
    M=i; c=b2; t=mmul(QC,t,b2);
    R=mmul(QC,R,b);                    // UNCONDITIONAL: invariant R²≡t·a demands it
  }
  return mto(QC,R);
}

struct Pt { fe6 x{},y{},z{}; };
inline bool PisInf(const Pt& P){ return mont::bn_isz(P.z.data(),6); }
inline Pt Pdbl(const Pt& P){
  const mont::MCtx& QC = ctx().m;
  if(PisInf(P) || mont::bn_isz(P.y.data(),6)){ return Pt{}; }
  const fe6 A=mmul(QC,P.x,P.x);
  const fe6 B=mmul(QC,P.y,P.y);
  const fe6 C=mmul(QC,B,B);
  const fe6 XB=madd(QC,P.x,B);
  fe6 D=mmul(QC,XB,XB);
  D=msub(QC,D,A);
  D=msub(QC,D,C);
  D=madd(QC,D,D);                                    // 2[(X+B)^2 - A - C]
  const fe6 E=madd(QC,madd(QC,A,A),A);               // 3A
  const fe6 X3=msub(QC,mmul(QC,E,E),madd(QC,D,D));   // E^2 - 2D
  const fe6 C2=madd(QC,C,C);
  const fe6 C4=madd(QC,C2,C2);
  const fe6 C8=madd(QC,C4,C4);                       // EXACTLY 8C (DEC-180)
  const fe6 Y3=msub(QC,mmul(QC,E,msub(QC,D,X3)),C8); // E(D-X3) - 8C
  const fe6 Z3=mmul(QC,madd(QC,P.y,P.y),P.z);        // 2YZ
  return Pt{X3,Y3,Z3};
}
inline Pt Padd(const Pt& P, const Pt& Q){
  const mont::MCtx& QC = ctx().m;
  if(PisInf(P)) return Q;
  if(PisInf(Q)) return P;
  fe6 Z1=mmul(QC,P.z,P.z), Z2=mmul(QC,Q.z,Q.z);
  fe6 U1=mmul(QC,P.x,Z2), U2=mmul(QC,Q.x,Z1);
  fe6 S1=mmul(QC,mmul(QC,P.y,Z2),Q.z);
  fe6 S2=mmul(QC,mmul(QC,Q.y,Z1),P.z);
  if(U1==U2) return (S1==S2)? Pdbl(P) : Pt{};
  fe6 H=msub(QC,U2,U1), HH=mmul(QC,H,H);
  fe6 I=madd(QC,HH,HH); I=madd(QC,I,I);
  fe6 J=mmul(QC,H,I);
  fe6 rr=msub(QC,S2,S1); rr=madd(QC,rr,rr);
  fe6 V=mmul(QC,U1,I);
  fe6 X3=msub(QC,msub(QC,mmul(QC,rr,rr),J),madd(QC,V,V));
  fe6 SJ=madd(QC,mmul(QC,S1,J),mmul(QC,S1,J));
  fe6 Y3=msub(QC,mmul(QC,rr,msub(QC,V,X3)),SJ);
  fe6 two{}; two[0]=2;
  fe6 Z3=mmul(QC,mmul(QC,mmul(QC,P.z,Q.z),H),mfrom(QC,two));
  return Pt{X3,Y3,Z3};
}
inline Pt Pmul(const Pt& P, const fe6& k){
  Pt r{};
  for(int i=5;i>=0;--i){
    for(int b=63;b>=0;--b){
      r=Pdbl(r);
      if((k[i]>>b)&1ULL) r=Padd(r,P);
    }
  }
  return r;
}

// ── affine helpers (canonical domain) ──
inline Pt from_affine(const u64 xa[6], const u64 ya[6]){
  const mont::MCtx& QC = ctx().m;
  fe6 x{}, y{};
  mont::bn_cpy(x.data(), xa, 6); mont::bn_cpy(y.data(), ya, 6);
  Pt P; P.x=mfrom(QC,x); P.y=mfrom(QC,y); P.z=QC.r1;
  return P;
}
inline bool to_affine(const Pt& P, u64 xa[6], u64 ya[6]){
  const mont::MCtx& QC = ctx().m;
  if(PisInf(P)) return false;
  const fe6 zi = mpow(QC, P.z, ctx().m2);   // Montgomery inverse of Z (Fermat)
  const fe6 z2 = mmul(QC, zi, zi);
  const fe6 x  = mto(QC, mmul(QC, P.x, z2));
  const fe6 y  = mto(QC, mmul(QC, P.y, mmul(QC, z2, zi)));
  mont::bn_cpy(xa, x.data(), 6); mont::bn_cpy(ya, y.data(), 6);
  return true;
}
inline Pt gen(){ return from_affine(blsq::Q_GEN_X, blsq::Q_GEN_Y); }
inline bool on_curve_aff(const u64 xa[6], const u64 ya[6]){
  const mont::MCtx& QC = ctx().m;
  fe6 x{}, y{};
  mont::bn_cpy(x.data(), xa, 6); mont::bn_cpy(y.data(), ya, 6);
  const fe6 Mx=mfrom(QC,x), My=mfrom(QC,y);
  return mmul(QC,My,My) == madd(QC,mmul(QC,mmul(QC,Mx,Mx),Mx), ctx().b);
}
} // namespace hsma::threshold::g1
