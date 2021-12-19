import random
import socket
import struct
import time

from io import BytesIO
from random import randint
from block import Block
from helper import (
    hash256,
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
)
NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'
TESTNET_NETWORK_MAGIC = b'\x0b\x11\x09\x07'

class NetworkEnvelope:
    def __init__(self, command, payload, testnet =False):
        self.command = command
        self.payload = payload
        if testnet:
            self.magic = TESTNET_NETWORK_MAGIC
        else:
            self.magic = NETWORK_MAGIC

    def __repr__(self):
        return '{}: {}'.format(
            self.command.decode('ascii'),
            self.payload.hex(),
        )
    @classmethod
    def parse(cls, s, testnet = False):
        magic = s.read(4)

        if magic == b'':
            raise IOError('Connection error')
        if testnet:
            expected_magic = TESTNET_NETWORK_MAGIC
        else:
            expected_magic = NETWORK_MAGIC
        if magic != expected_magic:
            raise SyntaxError('magic is not right {} vs {}'.format(magic.hex(),
                                                                   expected_magic.hex()))
        command = s.read(12)
        command = command.strip(b'\x00')
        payload_length = little_endian_to_int(s.read(4))
        checksum = s.read(4)
        payload = s.read(payload_length)
        calculated_checksum = hash256(payload)[:4]
        if calculated_checksum != checksum:
            raise IOError('checksum error')
        return cls(command,payload,testnet =testnet)

    def serialize(self):
        result = self.magic
        result += self.command + b'\x00' * (12 - len(self.command))
        result += int_to_little_endian(len(self.payload),4)
        result += hash256(self.payload)[:4]
        result += self.payload

        return  result


    def stream(self):
        return BytesIO(self.payload)
#  두 노드가 통신 할 때 필요한 정보
class VersionMessage:
    command = b'version'

    def __init__(self, version = 70015, services = 0, timestamp = None,
            receiver_services = 0,
            receiver_ip = b"127.0.0.1", receiver_port = 18333,
            sender_services = 0,
            sender_ip = b"127.0.0.1", sender_port =18333,
            nonce = None, user_agent = 0,
            latest_block = 0, relay=False):
        self.version = version
        self.services = services
        if timestamp is None:
            self.timestamp = int(time.time())
        else:
            self.timestamp = timestamp
        self.receiver_services = receiver_services
        self.receiver_ip = receiver_ip
        self.receiver_port = receiver_port
        self.sender_services = sender_services
        self.sender_ip = sender_ip
        self.sender_port = sender_port
        if nonce is None:

            self.nonce = struct.pack("Q", random.getrandbits(64))
        else:
            self.nonce = nonce
        self.user_agent = user_agent
        self.latest_block = latest_block
        self.relay = relay

    def serialize(self):
        result = int_to_little_endian(self.version,4)
        result += int_to_little_endian(self.services,8)
        result += int_to_little_endian(self.timestamp,8)
        result += int_to_little_endian(self.receiver_services,8)
        result += self.receiver_ip +int_to_little_endian(0,7)
        result += self.receiver_port.to_bytes(2,'big')
        result += int_to_little_endian(self.sender_services, 8)
        result += self.sender_ip +int_to_little_endian(0,7)
        result += self.sender_port.to_bytes(2, 'big')
        result += self.nonce
        # result += encode_varint(len(self.user_agent))
        result +=  struct.pack("B", 0)
        result += int_to_little_endian(self.latest_block, 4)
        if self.relay:
            result += b'\x01'
        else:
            result += b'\x00'
        return result

    @classmethod
    def parse(cls, s):
        version = little_endian_to_int(s.read(4))
        services = little_endian_to_int(s.read(8))
        timestamp = little_endian_to_int(s.read(8))
        receiver_services = little_endian_to_int(s.read(8))
        receiver_ip = s.read(16)
        receiver_port = s.read(2)
        sender_services = little_endian_to_int(s.read(8))
        sender_ip = s.read(16)
        sender_port = s.read(2)
        nonce = s.read(8)
        user_agent_length = read_varint(s)
        user_agent = s.read(user_agent_length)
        latest_block = little_endian_to_int(s.read(4))
        relay = True if s.read(1) == b'\x01' else False

        return cls(version, services, timestamp,
                   receiver_services,
                   receiver_ip, receiver_port,
                   sender_services,
                   sender_ip, sender_port,
                   nonce, user_agent,
                   latest_block, relay)

class VerAckMessage:
    command = b'verack'

    def __init__(self):
        pass
    @classmethod
    def parse(cls,s):
        return cls()

    def serialize(self):
        return b''
class PingMessage:
    command = b'ping'

    def __init__(self, nonce):
        self.nonce = nonce

    @classmethod
    def parse(cls, s):
        nonce = s.read(8)
        return cls(nonce)

    def serialize(self):
        return self.nonce
class PongMessage:
    command = b'pong'

    def __init__(self, nonce):
        self.nonce = nonce

    def parse(cls, s):
        nonce = s.read(8)
        return cls(nonce)

    def serialize(self):

        return self.nonce

class GetHeadersMessage:
    command = b'getheaders'

    def __init__(self, version =70015, num_hashes=1, start_block = None, end_block = None):
        self.version = version
        self.num_hashes = num_hashes
        if start_block is None:
            raise  RuntimeError('need start block')
        self.start_block = start_block
        if end_block is None:
            self.end_block = b'\x00' * 32
        else:
            self.end_block = end_block

    def serialize(self):
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(self.num_hashes)
        result += self.start_block[::-1]
        result += self.end_block[::-1]
        return result

class HeadersMessage:
    command = b'headers'

    def __init__(self, blocks):
        self.blocks = blocks

    @classmethod
    def parse(cls, stream):
        num_headers = read_varint(stream)
        blocks = []
        for _ in range(num_headers):
            blocks.append(Block.parse(stream))
            num_txs = read_varint(stream)
            if num_txs != 0:
                raise RuntimeError('number of txs not 0')
        return cls(blocks)

class SimpleNode:

    def __init__(self, host, port=None, testnet = False, logging = False):
        if port is None:
            if testnet:
                port = 18333
            else:
                port = 8333
        self.testnet = testnet
        self.logging = logging
        self.socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.socket.connect((host, port))
        self.stream = self.socket.makefile('rb' ,None)

    def send(self, message):
        envelope = NetworkEnvelope(
              message.command, message.serialize(), testnet = self.testnet)
        if self.logging:
            print('sending: {}'.format(message))

        self.socket.sendall(envelope.serialize())

    def read(self):
        envelope = NetworkEnvelope.parse(self.stream,testnet=self.testnet)
        if self.logging:
            print('receiving: {}'.format(envelope))
        return envelope

    def wait_for(self, *message_classes):
        command = None
        command_to_class = {m.command: m for m in message_classes}
        while command not in command_to_class.keys():

            envelope = self.read()
            command = envelope.command

            if command == VersionMessage.command:
                self.send(VerAckMessage())
            elif command == PingMessage.command:
                self.send(PongMessage(envelope.payload))
        return command_to_class[command].parse(envelope.stream())

    def handshake(self):
        version = VersionMessage()

        self.send(version)
        verack_received = False
        version_received = False
        while not (verack_received and version_received):

            message = self.wait_for(VerAckMessage, VersionMessage)
            if message.command == VerAckMessage.command:
                verack_received = True
            else:
                version_received = True

