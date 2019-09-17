from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as PKCSig
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import base64


# Web encoding stuff
def b64_encode(data):
    return base64.b64encode(data)

def b64_decode(data):
    return base64.b64decode(data)


class AssymetricEnc:
    def __init__(self, key=None):
        # Generate a new key
        self.my_key = key
        self.other_key = None
    
    def gen_new_key(self):
        self.my_key = RSA.generate(4096)

    def add_other_key(self, key):
        self.other_key = RSA.importKey(key)

    def Encrypt(self, data):
        data = self.rsa_encrypt(data)
        return b64_encode(data)

    def Decrypt(self, data):
        message = b64_decode(data)
        return self.rsa_decrypt(message)

    def rsa_encrypt(self, data):

        if self.other_key is None:
            raise ValueError(":(")

        encrypted = b""
        end_loop = False
        offset = 0
        chunk_size = 200
        rsa_cipher = PKCS1_OAEP.new(self.other_key)
        
        while not end_loop:
            chunk = data[offset:offset + chunk_size]

            if len(chunk) % chunk_size != 0:
                end_loop = True
                chunk += b" " * (chunk_size - len(chunk))
            
            encrypted += rsa_cipher.encrypt(chunk)

        return encrypted

    def rsa_decrypt(self, data):
        chunk_size = 256
        offset = 0
        decrypted = b""
        rsa_cipher = PKCS1_OAEP.new(self.my_key)

        while offset < len(data):
            chunk = data[offset:offset + chunk_size]
            decrypted += rsa_cipher.decrypt(chunk)
            offset += chunk_size

        return decrypted.strip()


#region HMAC Related stuff

def XOR(bytes1, bytes2):
    """Because python doesn't allow bitwise operations on bytearrays.
    Implementation is from https://nitratine.net/blog/post/xor-python-byte-strings/
    
    Args:
        bytes1 (bytes): Bytearray1
        bytes2 (bytes): Bytearray2
    """
    return bytes([_a ^ _b for _a, _b in zip(bytes1, bytes2)])


def HMAC(text, K):
    """Implementation of an HMAC function based on SHA-256 as outlined in RFC2104
    
    Args:
        text (bytes): Message to compute HMAC on
        K (bytes): Key to compute HMAX with
    
    Returns:
        bytes: Result of HMAC function
    """
    B = 64
    
    opad = b"\x5C" * B
    ipad = b"\36" * B

    # Only really works if a bytestring is inputtet
    assert isinstance(text, bytes)
    assert isinstance(K, bytes)

    if len(K) > B:
        K = SHA256.new(K).digest()

    K = K.ljust(B, b'\0')

    return SHA256.new(XOR(K, opad) + SHA256.new(XOR(K, ipad) + text).digest()).digest()
    
#endregion

#region PRF

def _P_hash_rec(secret, seed, value, A, depth):
    if depth < 1:
        return value
    A = HMAC(secret, A + seed)
    return _P_hash_rec(secret, seed, value+A, A, depth-1)

def P_hash(secret, seed, depth):
    return _P_hash_rec(secret, seed, b"", seed, depth)

def PRF(secret, label, seed, numbytes):
    """Pseudo random function as outlined in RFC5246
    
    Args:
        secret (bytes): The secret
        label (bytes): A label
        seed (bytes): A seed
        numbytes (int): The desired number of bytes, the size is only limited by the recursion limit
    
    Returns:
        bytes: A bytearray of length numbytes, containing the pseudo random data
    """
    assert isinstance(secret, bytes)
    assert isinstance(label, bytes)
    assert isinstance(seed, bytes)
    assert isinstance(numbytes, int)

    # We are using SHA256, so we get 32 bytes per unit of depth.
    # Therefore we need (numbytes // 32)+1 depth to get enough data
    output = P_hash(
        secret,
        label + seed,
        (numbytes // SHA256.digest_size)+1)
    
    # Truncate to desired size
    return output[:numbytes]

#endregion

def calculate_master_secret(pms, client_random, server_random):
    return PRF(pms, b"master secret", client_random + server_random, 48)

def generate_keys(master_secret, client_random, server_random):
    key_block = PRF(
        master_secret,
        b"key expansion",
        client_random + server_random,
        256)

    # Do some sort of split
    return key_block