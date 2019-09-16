from libencryption import Encryption
from handshake import Handshake
from flask import Flask, request, abort, jsonify
from uuid import uuid4

app = Flask(__name__)

OPEN_CONNECTIONS = {}

@app.route("/handshake", methods=["GET"])
def handshake():
    method = request.args.get("method")
    
    if method == "hello":
        client_random = request.args.get("client_random")
        if client_random is None:
            abort(400)

        session_id = request.args.get("sessionid")
        if session_id is None:
            session_id = uuid4().hex
        
        if session_id in OPEN_CONNECTIONS.keys():
            # You would resume normally, but we just redo the handshake
            del OPEN_CONNECTIONS[session_id]

        OPEN_CONNECTIONS[session_id] = Handshake()    
        return jsonify({
            "cert": OPEN_CONNECTIONS[session_id].send_request_cert(),
            "sessionid": session_id,
            "server_random": OPEN_CONNECTIONS[session_id].get_server_random()})

    elif method == "key_exchange":
        session_id = request.args.get("sessionid")
        if session_id is None:
            abort(400)

        if session_id not in OPEN_CONNECTIONS.keys():
            abort(400)

        
        
    else:
        abort(404)


if __name__ == '__main__':
    app.run()