import re
x=0x8508c00000000001
rr_=x**4-x**2+1; q=((x-1)**2*rr_)//3+x
assert q.bit_length()==377
R=pow(2,384,q)
s_=q-1
while s_%2==0: s_//=2
txt=open('build/tool.txt').read()
def grab(tag):
    m=re.search(rf"\[tsdump\] {tag}= ((?:[0-9a-f]{{16}} ?){{6}})",txt)
    return int(m.group(1).replace(" ",""),16)
y,w=grab("y"),grab("w")
inp,z,c,t0,R0=grab("input"),grab("z"),grab("c"),grab("t0"),grab("R0")
A=y*y%q                                   # the ACTUAL tonelli argument
print(f"[chk] input == y^2          : {inp==A}")
print(f"[chk] w^2 == input          : {pow(w,2,q)==inp}")
print(f"[chk] z is non-residue      : {pow(z,(q-1)//2,q)==q-1}")
print(f"[chk] c == z^s . R          : {c==pow(z,s_,q)*R%q}")
print(f"[chk] t0 == A^s . R         : {t0==pow(A,s_,q)*R%q}")
print(f"[chk] R0 == A^((s+1)/2) . R : {R0==pow(A,(s_+1)//2,q)*R%q}")
assert pow(A,(q-1)//2,q)==1, "A must be QR"
zz=2
while pow(zz,(q-1)//2,q)!=q-1: zz+=1
cc,tt=pow(zz,s_,q),pow(A,s_,q)
RRr=pow(A,(s_+1)//2,q); M=46
while tt!=1:
    i,t2=0,tt
    while t2!=1: t2=t2*t2%q; i+=1
    bb=pow(cc,1<<(M-i-1),q); M=i; cc=bb*bb%q; tt=tt*bb*bb%q; RRr=RRr*bb%q
print(f"[chk] python sqrt valid     : {pow(RRr,2,q)==A}")
print(f"[chk] tool w == ± py sqrt   : {w==RRr or w==(q-RRr)%q}")
