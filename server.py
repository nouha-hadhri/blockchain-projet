from flask import Flask, request, jsonify
from flask_cors import CORS

from main import process_attack

app = Flask(__name__)
CORS(app)

@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        # ✅ Données venant de Flutter
        data = request.get_json()

        # ✅ Envoi vers main.py
        result = process_attack(data)

        return jsonify({
            "status": "success",
            "prediction": result.to_dict(orient="records")
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)