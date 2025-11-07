from agents.collector import DataCollector
#from agents.detector_isolationforest import DetectorIF
from agents.detector_XGBoost import DetectorXGB
collector = DataCollector(input_path="data/auth_attempts_separe.xlsx")
df_processed = collector.load_data()

# ✅ Ajouter donnée API sans label
new_data = {
    "timestamp": "2025-11-07T14:30:00",
    "source_ip": "192.168.1.9",
    "user_agent": "curl/7.81.0",
    "response_time_ms": 400,
    "signature_valid": False,
    "attempts": 3,
    "geo": "FR"
}
collector.add_new_data(new_data)
# 3️⃣ Entraîner le modèle XGBoost
detector = DetectorXGB(processed_dir="data/processed", model_path="models/xgboost_model.pkl")
clf, metrics = detector.train(path="data/processed/processed_data.csv")

print("\n=== Metrics du modèle XGBoost ===")
for k, v in metrics.items():
    print(f"{k}: {v}")

# 4️⃣ Charger le dataset complet et isoler la donnée API (non labellisée)
latest = detector.load_processed()
api_data = latest[latest['is_attack'].isna()]  # La donnée API (sans label)

# 5️⃣ Prédire si la donnée API est une attaque
result = detector.predict_df(api_data)

print("\n===  Résultat de la prédiction pour la donnée API ===")
print(result[['attack_probability', 'is_attack_pred']])

#detector = DetectorIF(processed_dir="data/processed", model_path="models/isolation_forest.pkl")
#clf, metrics = detector.train(path="data/processed/processed_data.csv")

#latest = detector.load_processed()
#api_data = latest[latest['is_attack'].isna()]  # La donnée API
#result = detector.predict_df(api_data)

#print(result[['anomaly_score', 'is_attack_pred']])
