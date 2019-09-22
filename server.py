from handshake import Handshake
from flask import Flask, request, abort, jsonify
from uuid import uuid4
from libencryption import SymmetricEnc, generate_keys

app = Flask(__name__)

OPEN_CONNECTIONS = {}

@app.route("/msg", methods=["GET"])
def message():
    session_id = request.args.get("sessionid")
    msg = request.args.get("message")
    H = request.args.get("HMAC")

    if session_id is None or msg is None or H is None:
        abort(400)

    if session_id not in OPEN_CONNECTIONS.keys() or not isinstance(OPEN_CONNECTIONS[session_id], SymmetricEnc):
        abort(400)

    result = OPEN_CONNECTIONS[session_id].Decrypt(msg.encode('utf-8'), H.encode('utf-8')).decode('utf-8')
    if result is None:
        print("Failed to verify HMAC :(")

    print("Server received message containing:", result)

    result += " => Received by server and returned"

    new_msg, new_H = OPEN_CONNECTIONS[session_id].Encrypt(result.encode('utf-8'))

    return jsonify({"msg": new_msg.decode('utf-8'), "HMAC": new_H.decode('utf-8')}) 


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

        OPEN_CONNECTIONS[session_id] = Handshake(client_random)    
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

        pms = request.args.get("pms")
        if pms is None:
            abort(400)

        status = OPEN_CONNECTIONS[session_id].key_exchange(pms)
        
        (client_hmac, server_hmac, client_key, server_key), master_secret = OPEN_CONNECTIONS[session_id].get_shared_key()

        del OPEN_CONNECTIONS[session_id]

        OPEN_CONNECTIONS[session_id] = SymmetricEnc(server_hmac, client_hmac, server_key, client_key)

        return "Success" if status else "Failure"
        
    else:
        abort(404)


if __name__ == '__main__':
    app.run(port=7007)