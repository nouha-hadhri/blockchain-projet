# agents/security_actions.py

import didkit
import json
from pqcrypto.sign import dilithium2
import json

class SecurityActions:

    @staticmethod
    def trigger_did_auth(row):
        print("🔐 Vérification DID réelle…")

        # Charger la clé privée DID
        with open("did.json") as f:
            key = f.read()

        # Construire une Credential W3C
        credential = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "id": "urn:uuid:12345",
            "type": ["VerifiableCredential", "SecurityEvent"],
            "issuer": didkit.key_to_did("key", key),
            "issuanceDate": "2025-11-07T00:00:00Z",
            "credentialSubject": {
                "event": "Anomalous security activity",
                "source_ip": row.get("source_ip"),
                "probability": float(row["attack_probability"])
            }
        }

        # Signer la Credential
        proof = didkit.issue_credential(
            json.dumps(credential),
            '{}',   # options
            key
        )

        print("✔️ Credential DID signée (preuve JSON-LD créée).")
        print("→ VC =", proof[:200], "...")


    @staticmethod
    def apply_quantum_signature(row):
        print("🧬 Signature post-quantique réelle avec CRYSTALS-Dilithium…")

        # Message à signer (données de la ligne)
        message = json.dumps(row.to_dict()).encode()

        # Génération de clés quantiques
        public_key, private_key = dilithium2.generate_keypair()

        # Signature cryptographique PQC
        signature = dilithium2.sign(message, private_key)

        print("✔️ Signature quantique générée (Dilithium2).")
        print(f"Longueur signature : {len(signature)} octets.")
