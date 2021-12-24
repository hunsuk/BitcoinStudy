import hashlib
import math
import struct
import time
import random

import helper
import merkleblock
import tx as transaction
from urllib3.packages.six import BytesIO
from merkleblock import MerkleBlock,MerkleTree
from helper import *
import op
from ecc import S256Point, Signature, PrivateKey
from network import TX_DATA_TYPE
from script import p2pkh_script, Script

mySecret = 112334489442836185
mySecret2 = 199882814547789
#moax16wFkq2c9JyrSwzf9LVNw2goytPNJH
def print_hi():
    want = '6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937'
    script_pubkey = BytesIO(bytes.fromhex(want))
    script = Script.parse(script_pubkey)

    print(script.serialize().hex() == want)
if __name__ == '__main__':
    print_hi()


# See PyCharm help at https://www.jetbrains.com/help/pycharm/
