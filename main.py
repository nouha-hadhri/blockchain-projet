from agents.collector import DataCollector
from agents.detector_XGBoost import DetectorXGB
from agents.reactor import Reactor  

collector = DataCollector(input_path="data/auth_attempts_separe.xlsx")
df_processed = collector.load_data()

# Ajouter donnée API sans label
new_data = {
    "timestamp": "2025-11-07T14:33:00",
    "source_ip": "172.16.4.10",
    "user_agent": "Python-urllib/3.10",
    "response_time_ms": 300,
    "signature_valid": True,
    "attempts": 4,
    "geo": "US",
    
    
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

# ============================
#   CONFIGURATION EMAIL ICI
# ============================

reactor = Reactor(
    email_from="nouha.hadhri@enis.tn",
    email_password="cewdxwatrudddovz",
    email_to="hadil.hssaien@enis.tn"
)

# Lancer le système de réaction
reactor.react(result)
