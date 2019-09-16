from libencryption import Encryption
from handshake import Handshake
from flask import Flask, request, abort

app = Flask(__name__)


# Not an ideal way to store this, and also only allows one connection per IP
OPEN_CONNECTIONS = {}

@app.route("/handshake", methods=["GET"])
def handshake():
    method = request.args.get("method")
    
    if method == "hello":
        rem_addr = request.remote_addr
        if rem_addr in OPEN_CONNECTIONS.keys():
            # They already exist, but it seems they want to reauth
            del OPEN_CONNECTIONS[rem_addr]

        OPEN_CONNECTIONS[rem_addr] = Handshake()    
        return OPEN_CONNECTIONS[rem_addr].send_request_cert()

    elif method == "key_exchange":
        
    else:
        abort(404)


if __name__ == '__main__':
    app.run()