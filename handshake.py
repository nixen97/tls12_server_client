from libencryption import AssymetricEnc, b64_decode, b64_encode, calculate_master_secret, generate_keys
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
    def __init__(self, client_random):
        self.state = HSState.READY
        self.lasttransaction = time.time()

        self.mastersecret = None

        self.client_random = b64_decode(client_random.encode('utf-8'))
        self.server_random = os.urandom(32)

        with open(CERT_PATH, 'r') as fp:
            self.cert_string = fp.read()

        with open(PRIV_PATH, 'r') as fp:
            key = RSA.importKey(fp.read())
        
        # Parse server cert
        self.assymetric = AssymetricEnc(key=key) # key = parsed cert

    def get_server_random(self):
        return b64_encode(self.server_random).decode('utf-8')

    def send_request_cert(self):
        # Cert base64 encoded
        b64 = b64_encode(self.cert_string.encode('utf-8'))
        self.lasttransaction = time.time()
        return b64.decode('utf-8')

    def key_exchange(self, pre_master):
        # Der må ikke være gået mere 2 sekunder siden hello
        if (time.time() - self.lasttransaction) > 2:
            return False
        
        pms = self.assymetric.Decrypt(pre_master)
        
        self.mastersecret = calculate_master_secret(pms, self.client_random, self.server_random)

        self.state = HSState.DONE

        return True

    def get_shared_key(self):
        if (self.state != HSState.DONE):
            return None
        
        keys = generate_keys(self.mastersecret, self.client_random, self.server_random)
        return keys, self.mastersecret
