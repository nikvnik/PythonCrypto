
import argparse
import os


from random import randint
from pygost import gost34112012256
from pygost.utils import bytes2long
from constants import *
from elliptic_curve import *
from sympy import gcd
from asn import *

A = 1
B = 51597193811365919768190236681066502033803499635094541650610225403695076439048
p = 57896044628890729911196718984933305846544100325488685311213142875135838763683
q = 28948022314445364955598359492466652923270809441897180344196391207096541510137
x = 21371456824977467041033238171905463424508399897529674896678501178686263573482
y = 52962982709744467108853563358242537068648343861092009194618855518747612108192
curve = EllipticCurve(A, B)
P = Point(x, y)
Q = multiply(P, d, curve.a, p)


def generate_prime(q):

    while True:
        k = randint(1, q - 1)

        if gcd(k, q) == 1:
            return k

def add_sign(filename,data):
    hs = gost34112012256.new(data).digest()
    print('[+] Hash: {0}'.format(gost34112012256.new(data).hexdigest()))

    alpha = int.from_bytes(hs, byteorder='big')
    e = alpha % q
    if e == 0:
        e = 1

    while True:
        k = generate_prime(q) 

        C = multiply(P, k, curve.a, p)
        r = C.x % q
        if r == 0:
            continue

        s = (r * d + k * e) % q
        if s == 0:
            continue

        encoded_bytes = encode_signature(Q, p, curve, P, q, r, s)

        file = open(filename + '.sign', 'wb')
        file.write(encoded_bytes)
        file.close()

        return True

    
def sign(filename):
    file = open(filename, 'rb')
    data = file.read()
    file.close()

    if add_sign(filename, data):
        print('[+] Success added signature') 
    else:
        print('[-] Wrong added signature')


def verify_sign(filename, file_Signature):

    decoded_values = parse_file(file_Signature)

    s = decoded_values[-1]
    r = decoded_values[-2]
    q = decoded_values[-3]
    Q_x = decoded_values[0]
    Q_y = decoded_values[1]
    p = decoded_values[2]
    a = decoded_values[3]
    P_x = decoded_values[5]
    P_y = decoded_values[6]

    if r <= 0 or r >= q or s <= 0 or s >= q:
        print('[-] Invalid signature')

    file = open(filename, 'rb')
    data = file.read()
    file.close()

    hash = gost34112012256.new(data).digest()

    alpha = int.from_bytes(hash, byteorder='big')
    e = alpha % q
    if e == 0:
        e = 1

    v = invert(e, q)

    z_1 = (s * v) % q
    z_2 = (-r * v) % q

    tmp_1 = multiply(Point(P_x, P_y), z_1, a, p)
    tmp_2 = multiply(Point(Q_x, Q_y), z_2, a, p)
    C = add(tmp_1, tmp_2, a, p)
    R = C.x % q

    if R == r:
        return True
    else:
        return False

def parserCreate():

    parser = argparse.ArgumentParser()

    parser.add_argument("-s", "--sign", help="Add signature", action="store_true")
    parser.add_argument("-c", "--check", help="Check signature", action="store_true")
    parser.add_argument("--file", help="File")
    parser.add_argument("--signature", help="File_Signature")

    return parser



def main():
    parser = parserCreate()

    args = parser.parse_args()

    print('[+] a = {0}'.format(str(A)))
    print('[+] b = {0}'.format(str(B)))
    print('[+] p = {0}'.format(str(p)))
    print('[+] q = {0}'.format(str(q)))
    print('[+] x = {0}'.format(str(x)))
    print('[+] y = {0}'.format(str(y)))
    print()


    if args.sign:
        sign(args.file)
    elif args.check:
        if verify_sign(args.file,args.signature):
            print('[+] Sign is correct')
        else:
            print('[-] Sign is incorrect')



if __name__ == "__main__":
   main()
