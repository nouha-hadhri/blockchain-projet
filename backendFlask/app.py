from flask import Flask, request, jsonify
from flask_cors import CORS
import uuid
from eth_account.messages import encode_defunct
from eth_account import Account
from web3 import Web3

app = Flask(__name__)
CORS(app)  # Active CORS pour toutes les routes

# Stockage en mémoire
users = {}
challenges = {}

# Initialiser Web3
w3 = Web3()

@app.route("/auth/register", methods=["POST"])
def register():
    """Enregistrer un nouveau DID avec ses clés publiques"""
    data = request.get_json()
    
    did = data.get("did")
    public_keys = data.get("publicKeys")
    quorum = data.get("quorum")
    
    if not did or not public_keys or not isinstance(public_keys, list):
        return jsonify({"error": "DID et publicKeys requis"}), 400
    
    if not quorum or quorum > len(public_keys):
        return jsonify({
            "error": f"Quorum doit être entre 1 et {len(public_keys)}"
        }), 400
    
    users[did] = {
        "publicKeys": public_keys,
        "quorum": quorum
    }
    
    return jsonify({
        "success": True,
        "message": f"DID {did} enregistré avec {len(public_keys)} clés (quorum: {quorum})"
    })

@app.route("/auth/challenge/<did>", methods=["GET"])
def get_challenge(did):
    """Demander un challenge (début login)"""
    if did not in users:
        return jsonify({"error": "DID inconnu"}), 404
    
    nonce = str(uuid.uuid4())
    challenges[did] = nonce
    
    return jsonify({
        "did": did,
        "challenge": nonce
    })

@app.route("/auth/verify", methods=["POST"])
def verify():
    """Vérifier signatures (preuve DID + quorum)"""
    data = request.get_json()
    
    did = data.get("did")
    signatures = data.get("signatures")
    
    nonce = challenges.get(did)
    if not nonce:
        return jsonify({"error": "Challenge expiré ou inexistant"}), 400
    
    user = users[did]
    required = user["quorum"]
    
    valid_count = 0
    valid_keys = []
    
    for proof in signatures:
        entry = next((k for k in user["publicKeys"] if k["id"] == proof["keyId"]), None)
        if not entry:
            continue
        
        try:
            message = encode_defunct(text=nonce)
            recovered_address = Account.recover_message(message, signature=proof["signature"])
            
            if recovered_address.lower() == entry["key"].lower():
                valid_count += 1
                valid_keys.append(proof["keyId"])
        except Exception as e:
            print(f"Erreur vérification {proof['keyId']}: {str(e)}")
    
    if valid_count >= required:
        del challenges[did]
        return jsonify({
            "authenticated": True,
            "validKeys": valid_keys,
            "message": f"{valid_count}/{required} signatures valides"
        })
    
    return jsonify({
        "authenticated": False,
        "reason": f"Quorum non atteint ({valid_count}/{required})"
    })

@app.route("/auth/users", methods=["GET"])
def list_users():
    """Lister les DIDs enregistrés (dev only)"""
    user_list = [
        {
            "did": did,
            "keysCount": len(data["publicKeys"]),
            "quorum": data["quorum"]
        }
        for did, data in users.items()
    ]
    return jsonify(user_list)

if __name__ == "__main__":
    print("🚀 Server running on http://localhost:3000")
    print("✅ CORS enabled for all origins")
    app.run(host="0.0.0.0", port=3000, debug=True)