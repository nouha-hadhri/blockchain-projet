from agents.collector import DataCollector
from agents.detector_XGBoost import DetectorXGB
from agents.reactor import Reactor
import pandas as pd
from datetime import datetime

# ===========================
# INITIALISATION
# ===========================
collector = DataCollector(input_path="data/auth_attempts_separe.xlsx")
collector.load_data()

detector = DetectorXGB(
    processed_dir="data/processed",
    model_path="models/xgboost_model.pkl"
)

# ⚠ En production : entraîne une seule fois
clf, metrics = detector.train(path="data/processed/processed_data.csv")

reactor = Reactor(
    email_from="nouha.hadhri@enis.tn",
    email_password="cewdxwatrudddovz",
    email_to="hadil.hssaien@enis.tn"
)

# ===========================
# FONCTION APPELABLE PAR L'API
# ===========================
def process_attack(new_data: dict):
    """
    Fonction appelée par server.py
    Reçoit les données d'authentification DID
    """
    try:
        # ✅ Ajouter les nouvelles données
        collector.add_new_data(new_data)
        
        # ✅ Charger les données traitées
        latest = detector.load_processed()
        
        # ✅ Filtrer uniquement les nouvelles données (sans label)
        api_data = latest[latest['is_attack'].isna()]
        
        if api_data.empty:
            print("⚠️  Aucune donnée à analyser")
            return pd.DataFrame({
                'attack_probability': [0.0],
                'is_attack_pred': [False]
            })
        
        # ✅ Prédiction
        result = detector.predict_df(api_data)
        
        # ✅ Réaction (email si attaque)
        reactor.react(result)
        
        return result[['attack_probability', 'is_attack_pred']]
        
    except Exception as e:
        print(f"❌ Erreur dans process_attack: {e}")
        raise