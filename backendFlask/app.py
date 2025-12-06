from flask import Flask, request, jsonify
from flask_cors import CORS
import uuid
import requests
from datetime import datetime
from eth_account.messages import encode_defunct
from eth_account import Account
from web3 import Web3

app = Flask(__name__)
CORS(app)

# Stockage en mémoire
users = {}
challenges = {}
w3 = Web3()

# URL de votre API d'analyse AI
AI_ANALYSIS_URL = "http://localhost:5000/analyze"

def send_to_ai_analysis(auth_data):
    """Envoie les données d'authentification vers l'API d'analyse AI"""
    try:
        response = requests.post(AI_ANALYSIS_URL, json=auth_data, timeout=5)
        return response.json()
    except Exception as e:
        print(f"❌ Erreur envoi vers AI: {e}")
        return None

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
    challenges[did] = {
        "nonce": nonce,
        "timestamp": datetime.now().isoformat(),
        "attempts": 0
    }
    
    return jsonify({
        "did": did,
        "challenge": nonce
    })

def get_geo_from_ip(ip):
    """Obtenir la géolocalisation à partir de l'IP"""
    try:
        # API gratuite ipapi.co (limite: 1000 requêtes/jour)
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=2)
        if response.status_code == 200:
            data = response.json()
            return data.get('country_name', 'Unknown')
        return "Unknown"
    except:
        return "Unknown"

@app.route("/auth/verify", methods=["POST"])
def verify():
    """Vérifier signatures (preuve DID + quorum)"""
    start_time = datetime.now()
    data = request.get_json()
    
    did = data.get("did")
    signatures = data.get("signatures")
    
    # Récupérer les infos de la requête
    source_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    # ✅ Obtenir la géolocalisation
    geo = get_geo_from_ip(source_ip) if source_ip != "127.0.0.1" else "Local"
    
    challenge_data = challenges.get(did)
    if not challenge_data:
        return jsonify({"error": "Challenge expiré ou inexistant"}), 400
    
    nonce = challenge_data["nonce"]
    user = users[did]
    required = user["quorum"]
    
    # Incrémenter le nombre de tentatives
    challenge_data["attempts"] += 1
    
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
    
    # Calculer le temps de réponse
    end_time = datetime.now()
    response_time_ms = int((end_time - start_time).total_seconds() * 1000)
    
    # ✅ Préparer les données pour l'analyse AI
    auth_log = {
        "id": str(uuid.uuid4()),
        "timestamp": end_time.isoformat(),
        "source_ip": source_ip,
        "user_agent": user_agent,
        "response_time_ms": response_time_ms,
        "signature_valid": valid_count >= required,
        "attempts": challenge_data["attempts"],
        "did": did,
        "valid_signatures": valid_count,
        "required_signatures": required,
        "geo": geo  
    }
    
    # 🤖 Envoyer vers l'analyse AI (asynchrone)
    ai_result = send_to_ai_analysis(auth_log)
    
    # Vérifier si c'est une attaque détectée
    if ai_result and ai_result.get("status") == "success":
        predictions = ai_result.get("prediction", [])
        if predictions and len(predictions) > 0:
            is_attack = predictions[0].get("is_attack_pred", False)
            attack_prob = predictions[0].get("attack_probability", 0)
            
            if is_attack:
                print(f"⚠️  ATTAQUE DÉTECTÉE! Probabilité: {attack_prob}")
                # Tu peux bloquer l'authentification ici
                return jsonify({
                    "authenticated": False,
                    "reason": "Comportement suspect détecté",
                    "attack_probability": attack_prob
                }), 403
    
    if valid_count >= required:
        del challenges[did]
        return jsonify({
            "authenticated": True,
            "validKeys": valid_keys,
            "message": f"{valid_count}/{required} signatures valides",
            "ai_analysis": ai_result
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
    print("✅ CORS enabled")
    print("🤖 AI Analysis enabled on http://localhost:5000")
    app.run(host="0.0.0.0", port=3000, debug=True)