from logging import getLogger

from urllib3.packages.six import BytesIO

from helper import (
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
)
from op import (
    OP_CODE_FUNCTIONS,
    OP_CODE_NAMES, op_hash160, op_equal, op_verify,
)
LOGGER = getLogger(__name__)


def p2pkh_script(h160):
    return Script([0x76, 0xa9, h160, 0x88, 0xac])


class Script:
    def __init__(self, cmds=None):
        if cmds is None:
            self.cmds = []
        else:
            self.cmds = cmds

    def __repr__(self):
        result = []
        for cmd in self.cmds:
            if type(cmd) == int:
                if OP_CODE_NAMES.get(cmd):
                    name = OP_CODE_NAMES.get(cmd)
                else:
                    name = 'OP_[{}]'.format(cmd)
                result.append(name)
            else:
                result.append(cmd.hex())
        return ''.join(result)

    def __add__(self, other):
        return Script(self.cmds + other.cmds)
    @classmethod
    def parse(cls, s):
        length = read_varint(s)
        cmds = []
        count = 0
        while count < length:
            current = s.read(1)
            count += 1
            current_byte = current[0]
            #원소
            if current_byte >= 1 and current_byte < 75:
                n = current_byte
                cmds.append(s.read(n))
                count += n
            #PUHS 1
            elif current_byte == 76:
                data_length = little_endian_to_int(s.read(1))
                cmds.append(s.read(data_length))
                count +=data_length + 1
            #PUSH 2
            elif current_byte == 77:
                data_length = little_endian_to_int(s.read(2))
                cmds.append(s.read(data_length))
                count += data_length + 2

            else:
                op_code = current_byte
                cmds.append(op_code)
        if count != length:
            raise SyntaxError('parsing script failed')
        return cls(cmds)

    def raw_serialize(self):
        result = b''
        for cmd in self.cmds:
            # op code
            if type(cmd) == int:
                result += int_to_little_endian(cmd,1)
            # 원소 길이
            else:
                length = len(cmd)
                if length < 75:
                    result += int_to_little_endian(length,1)
                elif length > 75 and length < 0x100:
                    result += int_to_little_endian(76,1)
                    result += int_to_little_endian(length,1)
                elif length >= 0x100 and length <= 520 :
                    result += int_to_little_endian(77,1)
                    result += int_to_little_endian(length,2)

                else:
                    raise ValueError('too long an cmd')
                # 원소
                result += cmd
        return result

    def serialize(self):
        result = self.raw_serialize()
        total = len(result)
        return encode_varint(total) + result

    def evaluate(self, z):
        cmds = self.cmds[:]  # <1>
        stack = []
        altstack = []
        while len(cmds) > 0:
            cmd = cmds.pop(0)
            if type(cmd) == int:
                operation = OP_CODE_FUNCTIONS[cmd]
                if cmd in (99, 100):
                    if not operation(stack, cmds):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                elif cmd in (107, 108):
                    if not operation(stack, altstack):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                elif cmd in (172, 173, 174, 175):
                    if not operation(stack, z):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                else:
                    if not operation(stack):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
            else:
                stack.append(cmd)  # <7>
                if len(cmds) == 3 and cmds[0] ==0xa9 and type(cmds[1]) == bytes and len(cmd[1]) == 20 and cmds[2] == 0x87:
                    cmds. pop()
                    h160 = cmds.pop()
                    cmds.pop()
                    if not op_hash160(stack):
                        return False
                    stack.append(h160)
                    if not op_equal(stack):
                        return False
                    if not op_verify(stack):
                        LOGGER.info('bad p2sh h160')
                        return False
                    redeem_script = encode_varint(len(cmd)) + cmd
                    stream = BytesIO(redeem_script)
                    cmds.extend(Script.parse(stream).cmds)

        if len(stack) == 0:
            return False  # <8>
        if stack.pop() == b'':
            return False  # <9>
        return True  # <10>

    def is_p2pkh_script_pubkey(self):
        return len(self.cmds) == 5 and self.cmds[0] == 0x76 \
               and self.cmds[1] == 0xa9 \
               and type(self.cmds[2]) == bytes and len(self.cmds[2]) == 20 \
               and self.cmds[3] == 0x88 and self.cmds[4] == 0xac

    def is_p2sh_script_pubkey(self):
        return len(self.cmds) == 3 and self.cmds[0] == 0xa9 \
               and type(self.cmds[1]) == bytes and len(self.cmds[1]) == 20 \
               and self.cmds[2] == 0x87