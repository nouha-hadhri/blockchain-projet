import sys
import json
import os
from eth_account import Account
from eth_account.messages import encode_defunct

def main():
    if len(sys.argv) < 2:
        print("Usage: python sign.py <challenge>")
        sys.exit(1)
    
    challenge = sys.argv[1]
    keys_file = ".keys.json"
    
    # Si les clés existent déjà, les charger
    if os.path.exists(keys_file):
        print(" Chargement des clés existantes...\n")
        with open(keys_file, "r") as f:
            saved_keys = json.load(f)
        accounts = [Account.from_key(k["privateKey"]) for k in saved_keys]
    else:
        print(" Génération de nouvelles clés...\n")
        accounts = [Account.create() for _ in range(3)]
        
        keys_to_save = [
            {
                "id": f"key{i + 1}",
                "address": acc.address,
                "privateKey": acc.key.hex()
            }
            for i, acc in enumerate(accounts)
        ]
        
        with open(keys_file, "w") as f:
            json.dump(keys_to_save, f, indent=2)
        
        print(" Clés sauvegardées dans .keys.json\n")
    
    print("=== Public Keys (à copier dans le serveur) ===")
    for i, acc in enumerate(accounts):
        print(f"key{i + 1}: {acc.address}")
    
    print("\n=== Signatures (payload pour /auth/verify) ===")
    signatures = []
    
    for i, acc in enumerate(accounts):
        message = encode_defunct(text=challenge)
        signed_message = acc.sign_message(message)
        
        signatures.append({
            "keyId": f"key{i + 1}",
            "signature": signed_message.signature.hex()
        })
    
    print(json.dumps(signatures, indent=2))

if __name__ == "__main__":
    main()