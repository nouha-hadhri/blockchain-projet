from agents.collector import DataCollector
from agents.detector_XGBoost import DetectorXGB
from agents.reactor import Reactor  

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
# FONCTION APPELABLE PAR L’API
# ===========================

def process_attack(new_data: dict):
    """
    Fonction appelée par server.py
    """
    collector.add_new_data(new_data)

    latest = detector.load_processed()
    api_data = latest[latest['is_attack'].isna()]

    result = detector.predict_df(api_data)

    reactor.react(result)

    return result[['attack_probability', 'is_attack_pred']]