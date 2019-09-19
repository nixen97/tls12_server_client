import argparse
import requests
import os
from libencryption import AssymetricEnc, PRF, b64_decode, b64_encode, calculate_master_secret, generate_keys, SymmetricEnc

# Used for parsing the certificate, not for any crypto stuff
from OpenSSL.crypto import load_certificate, dump_publickey, FILETYPE_PEM

parser = argparse.ArgumentParser(description="Client that sends a message to a server 'securely'")

parser.add_argument('messages', metavar='msg', type=str, nargs='+', help="The message(s) to be sent")
parser.add_argument('--servip', type=str, help="The ip or address of the server")
parser.add_argument('--servport', type=int, help="The port of the server")

args = parser.parse_args()

msgs = args.messages
base_url = "http://"
base_url += args.servip
base_url += ":"
base_url += str(args.servport)

print("Sending requests to:", base_url)

# Generate new keys for the client.
enc = AssymetricEnc()
# enc.gen_new_key()

def perform_handshake():
    
    # Generate the clients random number
    client_random = os.urandom(32)

    # Hello
    params = {
        "method": "hello",
        "client_random": b64_encode(client_random).decode('utf-8')
    }

    # Send the hello request to the server
    res = requests.get(base_url + "/handshake", params=params)

    if res.status_code != 200:
        raise ValueError()

    # Parse the response

    json = res.json()

    # Parse the base64 values from the json
    cert_string = b64_decode(json["cert"].encode('utf-8'))
    server_random = b64_decode(json["server_random"].encode('utf-8'))

    # Keep this encoded, as we only need to pass it back and forth
    sessionId = json["sessionid"].encode('utf-8')

    # Parse the cert object
    cert = load_certificate(FILETYPE_PEM, cert_string)
    pub_key = dump_publickey(FILETYPE_PEM, cert.get_pubkey())

    # Add server public key to encryption object for later
    enc.add_other_key(pub_key)

    # This is where you would do some sort of verification of the certificate
    # In this example we just print some info
    meta = cert.get_issuer().get_components()
    print("-"*15)
    print("Certificate info:")
    print("Country:", meta[0][1].decode('utf-8'))
    print("State:", meta[1][1].decode('utf-8'))
    print("City:", meta[2][1].decode('utf-8'))
    print("Organization:", meta[3][1].decode('utf-8'))
    print("Domain:", meta[4][1].decode('utf-8'))
    print("-"*15)


    # Assuming we are now happy with the server certificate, we can now compute a pre-master secret
    
    # Start by a protocol version. In this case we do 12 for TLS 1.2, although this is not what you would do in real TLS
    pms = bytes([1,2])

    # 46 random bytes
    pms += os.urandom(46)

    # This is encrypted with the servers public key.
    # In this implementation it is base64 encoded, to be sent in a get-request
    msg = enc.Encrypt(pms)

    # We sent this to the server in another get request
    params = {
        "method": "key_exchange",
        "sessionid": sessionId,
        "pms": msg.decode('utf-8')
    }

    res = requests.get(base_url + "/handshake", params)
    if res.status_code != 200:
        print(res.status_code)
        raise ValueError()
    
    mastersecret = calculate_master_secret(pms, client_random, server_random)

    client_hmac, server_hmac, client_key, server_key = generate_keys(mastersecret, client_random, server_random)

    sym = SymmetricEnc(client_hmac, server_hmac, client_key, server_key)

    return sessionId, sym


def send_messages(msgs, sessionid, symetricenc):
    assert isinstance(msgs, list)

    for msg in msgs:
        enc, H = symetricenc.Encrypt(msg.encode('utf-8'))
        params = {
            "sessionid": sessionid,
            "message": enc.decode('utf-8'),
            "HMAC": H.decode('utf-8')
        }
        res = requests.get(base_url + "/msg", params)

        if res.status_code == 200:
            print("Received postive response from server")
        else:
            print("Received error from server")

        json = res.json()
        result = symetricenc.Decrypt(json["msg"].encode('utf-8'), json["HMAC"].encode('utf-8')).decode('utf-8')
        print(result)

if __name__ == "__main__":
    sessionid, sym = perform_handshake()
    send_messages(msgs, sessionid, sym)