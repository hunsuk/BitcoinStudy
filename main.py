import math

import tx as transaction
from urllib3.packages.six import BytesIO

import op

mySecret = 199808281234
#tx = f6f6bfaf0c24327e49ebcb59c203c21da00b21ffcc922b5e7b30f824e20d781b
import datetime
from ecc import FieldElement, S256Field,S256Point,PrivateKey, Signature,Point
from helper import hash256, hash160, encode_base58, little_endian_to_int
from tx import TxFetcher, Tx
import time
from sys import stdin
from script import Script
import sys
from helper import decode_base58, SIGHASH_ALL
from script import p2pkh_script, Script
from tx import TxIn, TxOut, Tx
from ecc import PrivateKey
from helper import SIGHASH_ALL
def print_hi():
    s,e = map(int,sys.stdin.readline().split())
    a = [False,False] + [True] * (e - 2)
    prime = []
    for i in range(2, e):
        if a[i]:
            prime.append(i)
            for j in range(2 * i, e , i):
                a[j] = False

    for i in prime:
        if(s % i ==0):
            print('{} {}'.format('BAD',i))
            return 0
    print('GOOD')
if __name__ == '__main__':
    print_hi()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
