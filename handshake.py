from libencryption import Encryption
from enum import Enum
import time

# Only using openSSL to parse the cert.
from OpenSSL.crypto import FILETYPE_PEM, load_certificate
from Crypto.PublicKey import RSA
import os

CERT_PATH='./server_keys/cert.pem'
PRIV_PATH='./server_keys/key.pem'

class HSState(Enum):
    READY = 0
    WAITING_FOR_CERT = 1
    DONE = 2


class Handshake:
    def __init__(self):
        self.state = HSState.READY
        self.lasttransaction = time.time()

        self.server_random = os.urandom(32)

        with open(CERT_PATH, 'r') as fp:
            self.cert_string = fp.read()

        with open(PRIV_PATH, 'r') as fp:
            key = RSA.importKey(fp.read())
        
        # Parse server cert
        self.encryption = Encryption(key=key) # key = parsed cert

    def get_server_random(self):
        return self.encryption.b64_encode(self.server_random).decode('utf-8')

    def send_request_cert(self):
        # Cert base64 encoded
        b64 = self.encryption.b64_encode(self.cert_string.encode('utf-8'))
        self.lasttransaction = time.time()
        return b64.decode('utf-8')

    def key_exchange(self, pre_master):
        # Der må ikke være gået mere x millisekunder
        pass

    def get_shared_key(self):
        if (self.state != HSState.DONE):
            return None
        pass
