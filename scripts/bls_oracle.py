x=0x8508c00000000001
r_=x**4-x**2+1; q=((x-1)**2*r_)//3+x
assert q.bit_length()==377 and r_.bit_length()==253
def L(v): return " ".join(f"{(v>>(64*i))&((1<<64)-1):016x}" for i in range(5,-1,-1))
R,RR=pow(2,384,q),pow(2,768,q)
s_,e_=q-1,0
while s_%2==0: s_//=2; e_+=1
print(f"[oracle] Q        {L(q)}");   print(f"[oracle] Rmod     {L(r_)}")
print(f"[oracle] Qm1      {L(q-1)}"); print(f"[oracle] halfq    {L((q-1)//2)}")
print(f"[oracle] sodd     {L(s_)}");  print(f"[oracle] Q.r1     {L(R)}")
print(f"[oracle] Q.rr     {L(RR)}");  print(f"[oracle] e={e_}")
for a in (2,3,7):
    assert pow(a,q-1,q)==1 and pow(a*a,(q-1)//2,q)==1
    print(f"[oracle] f({a})    {L(R)}"); print(f"[oracle] e({a})    {L(R)}")
