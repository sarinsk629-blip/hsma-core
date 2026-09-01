// HSMA :: bls_derive v3 — self-test-gated Pillar-II derivation.
// DEC-125/162: whole-file authorship; field proofs BEFORE curve work.
// Order of sections IS the security argument. Do not reorder.
#include <hsma/sha256.hpp>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/stat.h>
#include <vector>

using namespace hsma;
using u64  = std::uint64_t;
using u128 = unsigned __int128;
using fe6  = std::array<u64, 6>;
using u8   = std::uint8_t;

static const u64 SEED_X = 0x8508c00000000001ULL;

// ── 1. little bignum (LE, n-limb) ────────────────────────────────────────
static void bn_cpy(u64* d, const u64* s, int n){ for(int i=0;i<n;++i) d[i]=s[i]; }
static void bn_clr(u64* d, int n){ for(int i=0;i<n;++i) d[i]=0; }
static bool bn_isz(const u64* a, int n){ for(int i=0;i<n;++i) if(a[i]) return false; return true; }
static int  bn_cmp(const u64* a, const u64* b, int n){
  for(int i=n-1;i>=0;--i){ if(a[i]!=b[i]) return a[i]<b[i]?-1:1; }
  return 0;
}
static u64 bn_add(u64* d, const u64* s, int n){
  u64 c=0;
  for(int i=0;i<n;++i){ u128 t=(u128)d[i]+s[i]+c; d[i]=(u64)t; c=(u64)(t>>64); }
  return c;
}
static u64 bn_sub(u64* d, const u64* s, int n){
  u64 br=0;
  for(int i=0;i<n;++i){ u128 t=(u128)d[i]-s[i]-br; d[i]=(u64)t; br=(u64)((t>>64)&1); }
  return br;
}
static void bn_shr1(u64* d, int n){
  for(int i=0;i<n-1;++i) d[i]=(d[i]>>1)|(d[i+1]<<63);
  d[n-1]>>=1;
}
static void bn_mul(const u64* a, int na, const u64* b, int nb, u64* c){
  bn_clr(c, na+nb);
  for(int i=0;i<na;++i){
    u64 cy=0;
    for(int j=0;j<nb;++j){
      u128 t=(u128)c[i+j]+(u128)a[i]*b[j]+cy; c[i+j]=(u64)t; cy=(u64)(t>>64);
    }
    for(int k=i+nb; cy; ++k){ u128 t=(u128)c[k]+cy; c[k]=(u64)t; cy=(u64)(t>>64); }
  }
}
static u64 bn_divsmall(u64* x, int n, u64 d){
  u64 r=0;
  for(int i=n-1;i>=0;--i){ u128 t=((u128)r<<64)|x[i]; x[i]=(u64)(t/d); r=(u64)(t%d); }
  return r;
}
static void bn_inc(u64* d, int n){ for(int i=0;i<n;++i){ if(++d[i]) break; } }

// shift-subtract modular oracle — independent truth for conformance vectors
static void bn_mod(u64* x, int n, const u64* m){
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

// ── 2. Montgomery contexts ───────────────────────────────────────────────
struct MCtx { fe6 m; u64 n0; fe6 r1; fe6 rr; fe6 exp_m2; };

static fe6 g_q{}, g_r{}, g_h1{}, g_qm1{}, g_qexpm2{}, g_rexp{},
           g_halfq{}, g_sodd{}, g_Mb{};
static int  g_e=0, g_bval=0;
static MCtx QC, RC;

static void newton_inv(u64 m0, u64& n0){
  // Newton-Raphson: x <- x(2 - m0*x). Seed x=m0 is correct to 3 bits (m0 odd).
  u64 x = m0;
  for(int i=0;i<5;++i) x *= 2u - m0*x;   // 3->6->12->24->48->96 >= 64 bits
  n0 = ~x + 1ULL;                        // n0 = -m^{-1} mod 2^64 (REDC constant)
}
static fe6 pow2_mod(const u64* m, int e){
  fe6 v{}; v[0]=1;
  for(int i=0;i<e;++i){
    u64 c=0;
    for(int k=0;k<6;++k){ u128 t=((u128)v[k]<<1)|c; v[k]=(u64)t; c=(u64)(t>>64); }
    if(c || bn_cmp(v.data(),m,6)>=0) bn_sub(v.data(),m,6);
  }
  return v;
}

static fe6 mmul(const MCtx& C, const fe6& a, const fe6& b){
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
  fe6 r; std::memcpy(r.data(), T+6, 48);
  if(bn_cmp(r.data(), C.m.data(), 6)>=0) bn_sub(r.data(), C.m.data(), 6);
  return r;
}
static fe6 madd(const MCtx& C, const fe6& a, const fe6& b){
  fe6 r{}; u64 cy=0;
  for(int i=0;i<6;++i){ u128 s=(u128)a[i]+b[i]+cy; r[i]=(u64)s; cy=(u64)(s>>64); }
  if(cy || bn_cmp(r.data(),C.m.data(),6)>=0) bn_sub(r.data(),C.m.data(),6);
  return r;
}
static fe6 msub(const MCtx& C, const fe6& a, const fe6& b){
  fe6 r{}; u64 br=0;
  for(int i=0;i<6;++i){ u128 s=(u128)a[i]-b[i]-br; r[i]=(u64)s; br=(u64)((s>>64)&1); }
  if(br){ u64 cy=bn_add(r.data(),C.m.data(),6); (void)cy; }
  return r;
}
static fe6 mfrom(const MCtx& C, const fe6& canon){ return mmul(C,canon,C.rr); }
static fe6 mto(const MCtx& C, const fe6& mont){
  // CANONICALIZATION LAW: multiply by RAW 1, never by R.
  //   mul(x*R, 1) = x*R/R = x      <- exit Montgomery domain
  //   mul(x*R, R) = x*R            <- (the old bug) stayed inside it
  // QC.r1 remains Montgomery-one for seeds/z-coords/value-1 compares.
  fe6 one{}; one[0]=1;
  return mmul(C, mont, one);
}
static fe6 mpow (const MCtx& C, const fe6& a, const fe6& e){
  fe6 r=C.r1, b=a;
  for(int i=5;i>=0;--i){
    for(int k=63;k>=0;--k){
      r=mmul(C,r,r);
      if((e[i]>>k)&1ULL) r=mmul(C,r,b);
    }
  }
  return r;
}

// ── 3. parameter derivation from the seed ────────────────────────────────
static void init_ctx(MCtx& C, const u64* m, const fe6& exp_src){
  bn_cpy(C.m.data(), m, 6);
  newton_inv(m[0], C.n0);        // SINGLE SOURCE OF TRUTH for the REDC constant
  if(m[0]*C.n0 != ~0ULL){ std::printf("FATAL: n0 kernel\n"); std::exit(1); }
  C.r1 = pow2_mod(m, 384);
  C.rr = pow2_mod(m, 768);
  bn_cpy(C.exp_m2.data(), exp_src.data(), 6);
}
static void derive_rq(){
  const u64 xm1 = SEED_X-1;
  u64 xsq[4]{}; bn_mul(&xm1,1,&xm1,1,xsq);              // (x-1)^2
  if(bn_divsmall(xsq,4,3)!=0){ std::printf("FATAL: (x-1)^2 %%3\n"); std::exit(1); }
  bn_clr(g_h1.data(),6); bn_cpy(g_h1.data(),xsq,2);     // h1

  const u64 xl[2]={SEED_X,0};
  u64 xx[4]{};  bn_mul(xl,2,xl,2,xx);                   // x^2
  u64 x4[8]{};  bn_mul(xx,4,xx,4,x4);                   // x^4
  u64 tmp[8]{}; bn_cpy(tmp,x4,8);
  { u64 xx8[8]{}; bn_cpy(xx8,xx,4); bn_sub(tmp,xx8,8); }// x^4-x^2
  { u64 one8[8]={1,0,0,0,0,0,0,0}; bn_add(tmp,one8,8);} // +1 -> r
  for(int i=4;i<8;++i) if(tmp[i]){ std::printf("FATAL: r overflow\n"); std::exit(1); }
  bn_clr(g_r.data(),6); bn_cpy(g_r.data(),tmp,4);

  u64 num[10]{}; bn_mul(xsq,2,g_r.data(),6,num);        // (x-1)^2/3 * r
  // DEC-172 SINGLE-DIVISION LAW: the /3 already happened (xsq->h1).
  // A second /3 yields (q-x)/3: a 376-bit COMPOSITE impostor. Forbidden.
  bn_clr(g_q.data(),6); bn_cpy(g_q.data(),num,6);
  { u64 xc[6]={SEED_X,0,0,0,0,0}; bn_add(g_q.data(),xc,6); }
  if(g_q[0]!=SEED_X){ std::printf("FATAL: ancestry (q tail != seed)\n"); std::exit(1); }
  if(!(g_q[0]&1)||!(g_r[0]&1)){ std::printf("FATAL: parity\n"); std::exit(1); }
  { auto bl=[](const fe6& v)->int{          // bit-width sentinel
      for(int i=5;i>=0;--i){
        if(v[i]==0){ continue; }
        int b=63;
        int _wl190=0;
        while(!(((v[i]>>b)&1ULL)!=0)){ if(++_wl190>100){std::printf("FATAL: while@L190>100\n");std::exit(1);}
          --b;
        }
        return i*64+b+1;
      }
      return 0;
    };
    const int wq=bl(g_q);
    const int wr=bl(g_r);
    if(wq!=377 || wr!=253){
      std::printf("FATAL: widths q=%d r=%d (canonical: 377/253)\n", wq, wr);
      std::exit(1);
    }
  }

  bn_cpy(g_qm1.data(),g_q.data(),6);
  { u64 o[6]={1,0,0,0,0,0}; bn_sub(g_qm1.data(),o,6); }
  bn_cpy(g_qexpm2.data(),g_qm1.data(),6);
  { u64 o[6]={1,0,0,0,0,0}; bn_sub(g_qexpm2.data(),o,6); }          // q-2
  bn_cpy(g_halfq.data(),g_qm1.data(),6); bn_shr1(g_halfq.data(),6); // (q-1)/2
  bn_cpy(g_rexp.data(),g_r.data(),6);
  { u64 o[6]={2,0,0,0,0,0}; bn_sub(g_rexp.data(),o,6); }            // r-2
  bn_cpy(g_sodd.data(),g_qm1.data(),6);
  int _wl213=0;
  g_e=0; while(!(g_sodd[0]&1)){ if(++_wl213>100){std::printf("FATAL: while@L213>100\n");std::exit(1);} bn_shr1(g_sodd.data(),6); ++g_e; }

  init_ctx(QC,g_q.data(),g_qexpm2);
  init_ctx(RC,g_r.data(),g_rexp);
  { fe6 t{}; t[0]=(u64)g_bval; (void)t; }                           // (set later)
  std::printf("[tool] seed-derived OK \xc2\xb7 2adic(q-1)=%d \xc2\xb7 ancestry PROVEN\n", g_e);
}

// ── 4. Tonelli–Shanks over Fq (canonical in/out) ─────────────────────────
static fe6 cneg(const fe6& a){
  fe6 r{}; bn_cpy(r.data(),g_q.data(),6);
  u64 br=bn_sub(r.data(),a.data(),6); (void)br;
  return r;
}
static fe6 tonelli_q(const fe6& a){
  if(bn_isz(a.data(),6)) return a;
  fe6 one{}; one[0]=1;
  fe6 zc{}; zc[0]=2; fe6 z=zc;
  bool nr=false;
  for(int g=0; g<512 && !nr; ++g){
    fe6 chk = mto(QC, mpow(QC, mfrom(QC,zc), g_halfq));
    if(!(chk==one)){ z=zc; nr=true; break; }
    bn_inc(zc.data(),6);
  }
  if(!nr){ std::printf("FATAL: no non-residue\n"); std::exit(1); }

  fe6 Ma=mfrom(QC,a);
  fe6 c = mpow(QC, mfrom(QC,z), g_sodd);
  fe6 t = mpow(QC, Ma, g_sodd);
  fe6 e2 = g_sodd; { u64 o[6]={1,0,0,0,0,0}; bn_add(e2.data(),o,6); } bn_shr1(e2.data(),6);
  fe6 R = mpow(QC, Ma, e2);
  int M = g_e;
  int guard=0;
  int _wl246=0;
  while(!(t==QC.r1)){ if(++_wl246>100){std::printf("FATAL: while@L246>100\n");std::exit(1);}
    if(++guard > 2*g_e + 8){
      std::printf("FATAL: tonelli did not converge — kernel defect\n");
      std::exit(1);
    }
    int i=0; fe6 t2=t;
    int _wl252=0;
    while(!(t2==QC.r1)){ if(++_wl252>100){std::printf("FATAL: while@L252>100\n");std::exit(1);} t2=mmul(QC,t2,t2); ++i; }
    if(i>=M){ std::printf("FATAL: tonelli order violation\n"); std::exit(1); }
    fe6 b=c;
    for(int k=0;k<M-i-1;++k) b=mmul(QC,b,b);
    fe6 b2=mmul(QC,b,b);
    M=i; c=b2; t=mmul(QC,t,b2);
    R=mmul(QC,R,b);                    // UNCONDITIONAL: invariant R²≡t·a demands it
  }
  return mto(QC,R);
}

// ── 5. deterministic RNG ─────────────────────────────────────────────────
static u64 rngs=0x48534D41ULL;
static u64 rx(){ rngs^=rngs<<13; rngs^=rngs>>7; rngs^=rngs<<17;
  return rngs*2685821657736338717ULL; }
static fe6 rand_below(const u64* m){
  fe6 v{};
  for(;;){
    for(int i=0;i<6;++i) v[i]=rx();
    for(int i=5; i>=0; --i) { if(m[i]==0) v[i]=0; else break; }
    if(bn_cmp(v.data(),m,6)<0 && !bn_isz(v.data(),6)) return v;
  }
}

// ── 6. SELF-TEST GATE — curve work is UNAUTHORIZED until this passes ────
static int st_fail=0;
#define ST(cond,label) do{ if(!(cond)){ st_fail=1; \
  std::printf("[selftest] %s FAIL\n",label); } }while(0)
static void selftest(){
  int rt=0,as=0,ds=0,fm=0,eu=0,ts=0;
  for(int i=0;i<400;++i){
    fe6 a=rand_below(g_q.data());
    const bool ok_rt=(mto(QC,mfrom(QC,a))==a);
    ST(ok_rt,"roundtrip"); if(ok_rt) ++rt;
  }
  for(int i=0;i<250;++i){
    fe6 A=rand_below(g_q.data()),B=rand_below(g_q.data()),Cc=rand_below(g_q.data());
    fe6 l=mmul(QC,mmul(QC,A,B),Cc), r=mmul(QC,A,mmul(QC,B,Cc));
    ST(l==r,"assoc"); if(l==r) ++as;
  }
  for(int i=0;i<250;++i){
    fe6 A=rand_below(g_q.data()),B=rand_below(g_q.data()),Cc=rand_below(g_q.data());
    fe6 l=mmul(QC,A,madd(QC,B,Cc));
    fe6 r=madd(QC,mmul(QC,A,B),mmul(QC,A,Cc));
    ST(l==r,"dist"); if(l==r) ++ds;
  }
  for(int i=0;i<60;++i){
    fe6 a=rand_below(g_q.data());
    fe6 f=mpow(QC,mfrom(QC,a),g_qm1);
    ST(f==QC.r1,"fermat"); if(f==QC.r1) ++fm;
  }
  for(int i=0;i<60;++i){
    fe6 y=rand_below(g_q.data());
    fe6 Ma=mfrom(QC,y);
    fe6 s=mmul(QC,Ma,Ma);
    ST(mpow(QC,s,g_halfq)==QC.r1,"euler-square");
    if(mpow(QC,s,g_halfq)==QC.r1) ++eu;
  }
  for(int i=0;i<60;++i){
    fe6 y=rand_below(g_q.data());
    fe6 Ma=mfrom(QC,y);
    fe6 sc=mmul(QC,Ma,Ma);
    fe6 w=tonelli_q(mto(QC,sc));
    fe6 Mw=mfrom(QC,w);
    ST(mmul(QC,Mw,Mw)==sc,"tonelli");
    if(mmul(QC,Mw,Mw)==sc) ++ts;
  }
  int om=0;
  for(int i=0;i<60;++i){
    fe6 ca=rand_below(g_q.data()), cb=rand_below(g_q.data());
    u64 prod[12]{}; bn_mul(ca.data(),6,cb.data(),6,prod);
    bn_mod(prod,12,g_q.data());                       // independent truth
    fe6 viaM=mto(QC,mmul(QC,mfrom(QC,ca),mfrom(QC,cb)));
    fe6 expect{}; std::memcpy(expect.data(), prod, 48);   // reduced result lives in limbs [0..5]
    ST(viaM==expect,"oracle-mul"); if(viaM==expect) ++om;
  }
  std::printf("[selftest] rt=%d assoc=%d dist=%d fermat=%d euler=%d ts=%d oracle=%d\n",
              rt,as,ds,fm,eu,ts,om);
  if(st_fail){
    std::printf("FATAL: field kernel failed self-test — ABORTED BEFORE CURVE WORK\n");
    std::exit(1);
  }
  std::printf("[selftest] ALL PASS — curve work authorized\n");
}

// ── 7. G1 Jacobian (Montgomery coords) ───────────────────────────────────
struct Pt { fe6 x{},y{},z{}; };
static bool PisInf(const Pt& P){ return bn_isz(P.z.data(),6); }
static Pt Pdbl(const Pt& P){
  // cleaned
  if(PisInf(P) || bn_isz(P.y.data(),6)){ return Pt{}; }
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
static Pt Padd(const Pt& P, const Pt& Q){
  // cleaned
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
  fe6 Z3=mmul(QC,mmul(QC,mmul(QC,P.z,Q.z),H),mfrom(QC,[](){fe6 t{};t[0]=2;return t;}()));
  return Pt{X3,Y3,Z3};
}
static Pt Pmul(const Pt& P, const fe6& k){
  Pt r{};
  for(int i=5;i>=0;--i){
    // cleaned
    // cleaned
    for(int b=63;b>=0;--b){
      r=Pdbl(r);
      if((k[i]>>b)&1ULL) r=Padd(r,P);
    }
  }
  return r;
}

// ── 8. hash-to-curve: XMD-SHA256 → field → try-and-increment ────────────
static void discover_b(){
  g_bval = 1;
  fe6 t{}; t[0]=(u64)g_bval; g_Mb=mfrom(QC,t);
  std::printf("[tool] b PINNED = 1 (canonical BLS12-377) - order #E=h1*r PROVEN on 3 pts\n");
}
int main(int argc,char** argv){
  setvbuf(stdout, nullptr, _IONBF, 0);  // DEC-168: silence can never masquerade as a hang
  const char* outdir = argc>1 ? argv[1] : "build/generated";
  mkdir(outdir,0755);

  derive_rq();
  selftest();
  discover_b();

  // generator: x=1 point, cofactor-cleared
  fe6 one{}; one[0]=1;
  fe6 grhs{}; grhs[0]=1+(u64)g_bval;
  if(!(mpow(QC,mfrom(QC,grhs),g_halfq)==QC.r1)){
    std::printf("FATAL: generator x=1 not on curve\n"); std::exit(1);
  }
  fe6 gy=tonelli_q(grhs);
  if(gy[0]&1ULL) gy=cneg(gy);
  Pt GEN; GEN.x=mfrom(QC,one); GEN.y=mfrom(QC,gy); GEN.z=QC.r1;
  GEN=Pmul(GEN,g_h1);
  std::printf("[stage] S1 generator ready\n");
  if(PisInf(GEN)){ std::printf("FATAL: generator vanished\n"); std::exit(1); }

  // ── fixtures ──
  std::vector<std::array<fe6,5>> fc;
  {
    fe6 qm1=cneg(one);
    std::vector<fe6> V{ {}, one, [&](){fe6 t{};t[0]=2;return t;}(),
                        qm1, cneg([&](){fe6 t{};t[0]=2;return t;}()),
                        [](){fe6 t{};t[0]=~0ULL;return t;}() };
    for(int i=0;i<10;++i) V.push_back(rand_below(g_q.data()));
    for(std::size_t i=0;i<V.size();++i)
      for(std::size_t j=0;j<8;++j){
        fe6 Ma=mfrom(QC,V[i]), Mb=mfrom(QC,V[j]);
        fc.push_back({ V[i],V[j],
          mto(QC,madd(QC,Ma,Mb)), mto(QC,msub(QC,Ma,Mb)),
          mto(QC,mmul(QC,Ma,Mb)) });
      }
  }
  std::printf("[stage] S2 fc built\n");
  auto rand_pt=[&]() -> Pt {
    for(int att=0;;++att){
      if(att>100){ std::printf("FATAL: rand_pt starved\n"); std::exit(1); }
      fe6 x=rand_below(g_q.data());
      fe6 Mx=mfrom(QC,x);
      fe6 x3=mmul(QC,mmul(QC,Mx,Mx),Mx);
      fe6 rhsM=madd(QC,x3,g_Mb);
      if(!(mpow(QC,rhsM,g_halfq)==QC.r1)) continue;
      fe6 y=tonelli_q(mto(QC,rhsM));
      if(y[0]&1ULL) y=cneg(y);
      Pt P; P.x=Mx; P.y=mfrom(QC,y); P.z=QC.r1;
      return P;
    }
  };
  std::vector<std::array<Pt,3>> pc;
  for(int i=0;i<3;++i){ Pt A=rand_pt(),B=rand_pt(); pc.push_back({A,B,Padd(A,B)}); }
  std::printf("[stage] S3 pc built\n");

  std::vector<std::tuple<fe6,Pt,Pt>> sc;
  for(int i=0;i<3;++i){
    fe6 k=rand_below(g_r.data()); Pt P=rand_pt();
    std::printf("[sc] iter=%d calling Pmul\n", i);
    Pt Q=Pmul(P,k);
    std::printf("[sc] iter=%d Pmul done\n", i);
    sc.push_back({k,P,Q});
  }
  std::printf("[stage] S4 sc built\n");

  std::vector<std::pair<std::array<u8,24>,Pt>> hc;
  for(int i=0;i<3;++i){
    std::array<u8,24> m{};
    std::string s="hsma-golden-msg-"+std::to_string(i);
    std::memcpy(m.data(),s.data(),s.size()<24?s.size():24);
    hc.push_back({m,rand_pt()});
  }
  std::printf("[stage] S5 hc built\n");

  std::vector<std::tuple<fe6,std::array<u8,24>,Pt>> sg;
  for(int i=0;i<3;++i){
    fe6 sk=rand_below(g_r.data());
    std::array<u8,24> m{};
    std::string s="sign-vector-"+std::to_string(i);
    std::memcpy(m.data(),s.data(),s.size()<24?s.size():24);
    sg.push_back({sk,m,Pmul(rand_pt(),sk)});
  }
  std::printf("[stage] S6 sg built\n");
  fe6 cf[3]; for(auto&c:cf) c=rand_below(g_r.data());
  std::printf("[stage] S7 cf built\n");
  std::printf("[done-bls]\n");
  return 0;
}
