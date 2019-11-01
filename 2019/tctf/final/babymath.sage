#encoding=utf-8

p=25221961025508539
F.<x>=GF(p^2, modulus=x^2+15859456511143016*x+12833828353685245)
R.<y>=PolynomialRing(F)

# step1: 在GF(p^2)上分解多项式
f=(y^3-y^2-y-1).factor()
lambda1=y-f[0][0]
lambda2=y-f[1][0]
lambda3=y-f[2][0]

# step2: 求数列通项公式，形式为an=c1*(lambda1^n)+c2*(lambda2^n)+c3*(lambda3^n)
M1=matrix([[F(1),F(1),F(1)],[lambda1,lambda2,lambda3],[lambda1^2,lambda2^2,lambda3^2]])
b1=matrix([[F(0)],[F(0)],[F(1)]])
x1=M1\b1

# step3: 解出lambda^n，再求离散对数
M2=matrix([[x1[0][0],x1[1][0],x1[2][0]],[x1[0][0]*lambda1,x1[1][0]*lambda2,x1[2][0]*lambda3],[x1[0][0]*(lambda1^2),x1[1][0]*(lambda2^2),x1[2][0]*(lambda3^2)]])
b2=matrix([[F(1914483117172565)],[F(15349972598427081)],[F(2510729161496127)]])
x2=M2\b2
flag=F(x2[0][0].numerator()).log(lambda1)
print('flag{%d}' % flag)
