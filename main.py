import socket
from network import NetworkEnvelope, VersionMessage
host = '192.168.219.195'
port = 18333

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((host,port))
stream = socket.makefile('rb',None)
version = VersionMessage()
envelope = NetworkEnvelope(version.command, version.serialize(), testnet = True)
socket.sendall(envelope.serialize())

while True:
    new_message = NetworkEnvelope.parse(stream)
    print(new_message)
