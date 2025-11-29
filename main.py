from agents.collector import DataCollector
from agents.detector_XGBoost import DetectorXGB
from agents.reactor import Reactor  

collector = DataCollector(input_path="data/auth_attempts_separe.xlsx")
df_processed = collector.load_data()

# Ajouter donnée API sans label
new_data = {
    "timestamp": "2025-11-07T03:21:00",
    "source_ip": "10.0.5.88",
    "user_agent": "Python-urllib/3.9 BOT Scanner",
    "response_time_ms": 900,
    "signature_valid": False,
    "attempts": 12,
    "geo": "RU"
}

collector.add_new_data(new_data)

# Entraîner le modèle
detector = DetectorXGB(processed_dir="data/processed", model_path="models/xgboost_model.pkl")
clf, metrics = detector.train(path="data/processed/processed_data.csv")

print("\n=== Metrics du modèle XGBoost ===")
for k, v in metrics.items():
    print(f"{k}: {v}")

# Données API
latest = detector.load_processed()
api_data = latest[latest['is_attack'].isna()]

# Prédiction
result = detector.predict_df(api_data)

print("\n=== Résultat Détecteur ===")
print(result[['attack_probability', 'is_attack_pred']])

# ✅ Réacteur (version correcte)
reactor = Reactor()
reactor.react(result)
