from sage.all import *
import random


def generate_random_curve():
    n = next_prime(10**7)
    k = GF(n)

    while True:
        a = random.randint(2, n-1)
        b = random.randint(2, n-1)

        if (4*a**3 + 27*b**2) != 0:
            curve = EllipticCurve(k, [a, b])

            P = curve.random_element()
            q = P.order()

            d = random.randint(2, q)
            Q = d * P

            

            return [curve, n, P, Q, d, q]


def generate_curve(n, a, b, d, x, y):
    curve = EllipticCurve(GF(n), [a, b])
    P = curve(x, y)
    Q = d * P
    q = P.order()

    return [curve, n, P, Q, d, q]


def H(P, L):
    return mod(P[0], L)


def Z(z, i):
    if i < 0:
        return 0
    else:
        return z[i]


def factor_to_list(Value):
    l = list(Value)
    r = list()

    for elem in l:
        tmp1, tmp2 = elem
        r.append(tmp1**tmp2)

    return r


def PoligHellmanAttack(curve, P, Q, q):
    P_infinity = curve(0, 1, 0)
    d = list()

    #Step 1
    for j in range(0, len(q)):
        p = q[j][0]
        a = q[j][1]
        S = P_infinity
        z = list()
        P0 = (q / p).value() * P

        #Step 1.4
        for k in range(0, a):
            S = S + int(Z(z, k-1) * p**(k-1)) * P

            tmp1 = (q / p**(k+1)).value()
            tmp2 = (Q - S)
            Qk = tmp1 * tmp2 
            #Qk = (q / p**(k+1)).value() * (Q - S)

            zk = P0.discrete_log(Qk)
            z.append(zk)

        #Step 1.5
        dk = 0
        for i in range(0, a):
            dk = dk + z[i] * p**(i)
        dk = dk % (p**a)
        d.append(dk)

    d = crt(d, factor_to_list(q))
    return d

ъ
def main():
    
    curve = generate_random_curve()
    print("[+] Parameters:\n\t{}\n\tn = {}\n\tP = {}\n\tQ = {}\n\td = {}\n\tq = {}\n".format(
        curve[0], curve[1], curve[2], curve[3], curve[4], curve[5]))


 # n, P, Q, q 
 # n - характеристика поля - модуль элиптической кривой
    d = PoligHellmanAttack(curve[0], curve[2], curve[3], factor(curve[5]))

    if d != None:
        print("[+] Found d = {}".format(d))

if __name__ == '__main__':
    main()
