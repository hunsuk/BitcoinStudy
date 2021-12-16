import math

import tx as transaction
from urllib3.packages.six import BytesIO

import op
from ecc import S256Point, Signature

mySecret = 199808281234
#tx = f6f6bfaf0c24327e49ebcb59c203c21da00b21ffcc922b5e7b30f824e20d781b
from helper import hash256, little_endian_to_int, bits_to_target, TWO_WEEKS,target_to_bits,calculate_new_bits
from block import Block

def print_hi():
    last_block = Block.parse(BytesIO(bytes.fromhex(
        '02000020f1472d9db4b563c35f97c428ac903f23b7fc055d1cfc26000000000000000000b3f449\
fcbe1bc4cfbcb8283a0d2c037f961a3fdf2b8bedc144973735eea707e1264258597e8b0118e5f00474')))
    first_block = Block.parse(BytesIO(bytes.fromhex('000000203471101bbda3fe307664b3283a9ef0e97d9a38a7eacd8800000000000000000010c8ab\
a8479bbaa5e0848152fd3c2289ca50e1c3e58c9a4faaafbdf5803c5448ddb845597e8b0118e43a81d3')))

    print(calculate_new_bits(last_block.bits,last_block.timestamp-first_block.timestamp).hex())
if __name__ == '__main__':
    print_hi()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
