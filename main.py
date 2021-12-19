import hashlib
import math
import struct
import time
import random

import tx as transaction
from urllib3.packages.six import BytesIO

import op
from ecc import S256Point, Signature

mySecret = 199808281234
#tx = f6f6bfaf0c24327e49ebcb59c203c21da00b21ffcc922b5e7b30f824e20d781b
from helper import hash256, little_endian_to_int, bits_to_target, TWO_WEEKS,target_to_bits,calculate_new_bits,int_to_little_endian
from block import Block, GENESIS_BLOCK, LOWEST_BITS
from network import NetworkEnvelope, SimpleNode, VersionMessage, VerAckMessage, GetHeadersMessage, HeadersMessage
import sys
def print_hi():
    from io import BytesIO
    from network import SimpleNode, GetHeadersMessage, HeadersMessage
    from block import Block, GENESIS_BLOCK, LOWEST_BITS
    from helper import calculate_new_bits
    previous = Block.parse(BytesIO(GENESIS_BLOCK))
    first_epoch_timestamp = previous.timestamp
    expected_bits = LOWEST_BITS
    count = 1
    node = SimpleNode('mainnet.programmingbitcoin.com', testnet=False)
    node.handshake()
    for _ in range(19):
        getheaders = GetHeadersMessage(start_block=previous.hash())
        node.send(getheaders)
        headers = node.wait_for(HeadersMessage)
        for header in headers.blocks:
            if not header.check_pow():
                raise RuntimeError('bad PoW at block {}'.format(count))
            if header.prev_block != previous.hash():
                raise RuntimeError('discontinuous block at {}'.format(count))
            if count % 2016 == 0:
                time_diff = previous.timestamp - first_epoch_timestamp
                expected_bits = calculate_new_bits(previous.bits, time_diff)
                print(expected_bits.hex())
                first_epoch_timestamp = header.timestamp
            if header.bits != expected_bits:
                raise RuntimeError('bad bits at block {}'.format(count))
            previous = header
            count += 1
print_hi()


# See PyCharm help at https://www.jetbrains.com/help/pycharm/
