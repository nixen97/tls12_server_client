from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import base64

class Encryption:
    def __init__(self, key=None):
        # Generate a new key
        self.my_key = key
        self.other_key = None
    
    def gen_new_key(self):
        self.my_key = RSA.generate(4096)

    def add_other_key(self, key):
        self.other_key = RSA.importKey(key)


    def Encrypt(self, message):
        data = message.encode('utf-8')
        data = self.rsa_encrypt(data)
        h = self.rsa_sign(data)
        return self.b64_encode(data), h

    def Decrypt(self, message, h):
        message = self.b64_decode(message)
        
        if not self.rsa_verify(message, h):
            print("Something error like")

        return self.rsa_decrypt(message)


    def b64_encode(self, data):
        return base64.b64encode(data)

    def b64_decode(self, data):
        return base64.b64decode(data)

    def rsa_encrypt(self, data):

        if self.other_key is None:
            raise ValueError(":(")

        encrypted = b""
        end_loop = False
        offset = 0
        chunk_size = 470

        while not end_loop:
            chunk = data[offset:offset + chunk_size]

            if len(chunk) % chunk_size != 0:
                end_loop = True
                chunk += b" " * (chunk - len(chunk))
            
            encrypted += self.other_key.encrypt(chunk)

        return encrypted

    def rsa_decrypt(self, data):
        chunk_size = 512
        offset = 0
        decrypted = b""

        while offset < len(data):
            chunk = data[offset:offset + chunk_size]
            decrypted += self.my_key.decrypt(chunk)
            offset += chunk_size

        return decrypted.strip()

    def rsa_sign(self, data):
        signer = PKCS1_v1_5.new(self.my_key)
        digest = SHA256.new()
        digest.update(data)
        return signer.sign(digest)

    def rsa_verify(self, data, h):
        signer = PKCS1_v1_5.new(self.other_key)
        digest = SHA256.new()
        digest.update(data)
        return signer.verify(digest, h)
