# -*- coding: UTF-8 -*-

'''
# http://cryptowiki.net/index.php?title=%D0%A1%D1%85%D0%B5%D0%BC%D0%B0_%D0%AD%D0%BB%D1%8C-%D0%93%D0%B0%D0%BC%D0%B0%D0%BB%D1%8F

Python x64 3.6.7

python -m pip install --upgrade pip
python -m pip install asn1
python -m pip install pycryptodome
python -m pip install pycryptodomex
python -m pip install sympy

E.g. run

python generateparamsElGamal.py 512 > parametrs.py
python mainElGamal.py --encrypt --file test.txt
..\..\dumpasn1\dumpasn1.exe test.txt.enc
python mainElGamal.py --decrypt --file test.txt.enc
fc /b test.txt test.txt.dec

'''

from argparse import ArgumentParser
from os import urandom, remove

from asn import encode, decode
from generateparamsElGamal import generate_x
from parametrs import *

# ===============================================

from Cryptodome.Cipher import DES3
from Cryptodome.Util.Padding import pad, unpad

# for 3d lab = 8, for 1st lab = 24
LENGTH_KEY = 24

iv = b'\x00\x00\x00\x00\x00\x00\x00\x00'

def encryptTripleDES(data, key):

    #des3 = DES3.new(key, DES3.MODE_ECB)
    _DES3 = DES3.new(key, DES3.MODE_CBC, iv)

    print('[] TripleDES key =', key)
    print('[] TripleDES key =', int.from_bytes(key, byteorder='big'))

    # pad - padding
    cipher = _DES3.encrypt(pad(data, DES3.block_size))

    return cipher


def decryptTripleDES(data, key):

    #des3 = DES3.new(key, DES3.MODE_ECB)
    _DES3 = DES3.new(key, DES3.MODE_CBC, iv)

    decryptedText = unpad(_DES3.decrypt(data), DES3.block_size)

    return decryptedText

# ===============================================


def func(m, b_y, p):

    return (m - b_y) % p


def func_inv(c, b_y, p):

    return (c + b_y) % p


def encrypElGamal(data):

    # gcd(y, p - 1) = 1
    y = generate_x(p, length_p)

    a_y = pow(a, y, p)

    c = func(data, pow(b, y, p), p)

    return a_y, c


def encrypt(filename):

    symmetricKey = urandom(LENGTH_KEY)

    with open(filename, 'rb') as file:
        data = file.read()
        cipherData = encryptTripleDES(data, symmetricKey)

    a_y, c = encrypElGamal(int.from_bytes(symmetricKey, byteorder='big'))

    encodedBytes = encode(
        b, # b
        p, # p
        a, # a
        a_y, c, # (a^y, c)
        len(cipherData), 
        cipherData)

    with open(filename + '.enc', 'wb') as file:
        file.write(encodedBytes)

    return

def decryptElGamal(a_y, c):

    return func_inv(c, pow(a_y, x, p), p)


def decrypt(filename):

    # restoredMod, e, encryptedKey = asn.decode(filename)
    b, p, a, a_y, c, cipher_len = decode(filename)

    print('b =', b)
    print('p =', p)
    print('a =', a)
    print('a_y =', a_y)
    print('c =', c)
    print('len =', cipher_len)

    restoredKey = decryptElGamal(a_y, c)

    restoredKey = restoredKey.to_bytes(LENGTH_KEY, 'big')

    with open('~tmp', 'rb') as file:
        data = file.read()
        decryptedText = decryptTripleDES(data, restoredKey)

    remove('~tmp')

    with open(filename[0:len(filename) - 4] + '.dec', 'wb') as file:
        file.write(decryptedText)

    return


def createParser():

    parser = ArgumentParser()

    parser.add_argument("-e", "--encrypt", action="store_true")
    parser.add_argument("-d", "--decrypt", action="store_true")
    parser.add_argument("--file", help="File")

    return parser


def main():

    parser = createParser()

    args = parser.parse_args()

    if args.encrypt:
        encrypt(args.file)
        print('[+] The file has been successfully encrypted')

    elif args.decrypt:
        decrypt(args.file)
        print('[+] The file has been successfully decrypted')


if __name__ == '__main__':
    main()


