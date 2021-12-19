import hashlib
SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
TWO_WEEKS = 60 * 60 * 24 * 14
MAX_TARGET = 0xffff * 256**(0x1d - 3)
def hash256(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()
def hash160(s):
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()
def encode_base58(s):
    count = 0
    for c in s:
        if c ==0:
            count += 1
        else:
             break
    num = int.from_bytes(s, 'big')
    prefix = '1' * count
    result =''
    while num > 0:
        num , mod = divmod(num , 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result

def encode_base58_checksum(b):
    return encode_base58(b + hash256(b)[:4])

def decode_base58(s):
    num = 0
    for c in s:
        num *=58
        num += BASE58_ALPHABET.index(c)
    combined = num.to_bytes(25,byteorder='big')
    checksum = combined[-4:]
    if hash256(combined[:-4])[:4] != checksum:
        raise ValueError('bad address: {} {}'.format(checksum,  hash256(combined[:-4])[:4]))
    return combined[1:-4]
def little_endian_to_int(b):
    return int.from_bytes(b,'little')

def int_to_little_endian(n, length):
    return n.to_bytes(length,'little')

def read_varint(s):
    i = s.read(1)[0]
    if i == 0xfd:
        return little_endian_to_int(s.read(2))
    elif i == 0xfe:
        return int_to_little_endian(s.read(4))
    elif i == 0xff:
        return little_endian_to_int(s.read(8))
    else:
        return i

def encode_varint(i):
    if i <0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + int_to_little_endian(i,2)
    elif i < 0x100000000:
        return b'\xfe' + int_to_little_endian(i,4)
    elif i < 0x10000000000000000:
        return b'\xff' + int_to_little_endian(i,8)
    else:
        raise ValueError('integer is too large ')

def h60_to_p2pkh_address(h160,testnet=False):
    if testnet:
        prefix = b'\x6f'
    else:
        prefix = b'\x00'
    return encode_base58_checksum(prefix + h160)

def h160_to_p2sh_address(h160, testnet=False):
    if testnet:
        prefix = b'\xc4'
    else:
        prefix = b'\x05'
    return encode_base58_checksum(prefix + h160)

def bits_to_target(bits):
    exponent = bits[-1]
    coefficient = little_endian_to_int(bits[:-1])
    return coefficient * 256 **(exponent -3)


def difficulty(self):
    lowest = 0xffff * 256**(0x1d - 3)
    return lowest / self.target()


def target_to_bits(target):
    raw_bytes = target.to_bytes(32, 'big')
    raw_bytes = raw_bytes.lstrip(b'\x00')
    if raw_bytes[0] > 0x7f:
        exponent = len(raw_bytes) + 1
        coefficient = b'\x00' + raw_bytes[:2]
    else:
        exponent = len(raw_bytes)  # <3>
        coefficient = raw_bytes[:3]  # <4>
    new_bits = coefficient[::-1] + bytes([exponent])  # <5>
    return new_bits
def calculate_new_bits(previous_bits, time_differential):
    if time_differential > TWO_WEEKS * 4:
        time_differential = TWO_WEEKS * 4
    if time_differential < TWO_WEEKS // 4:
        time_differential = TWO_WEEKS // 4
    new_target = bits_to_target(previous_bits) * time_differential // TWO_WEEKS
    if new_target > MAX_TARGET:
        new_target = MAX_TARGET
    return target_to_bits(new_target)