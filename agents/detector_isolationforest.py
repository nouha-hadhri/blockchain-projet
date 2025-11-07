import os
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)
from imblearn.over_sampling import SMOTE


class DetectorIF:
    """
    Détecteur basé sur Isolation Forest :
    - Entraîne un modèle sur les données prétraitées
    - Équilibre les classes via SMOTE
    - Évalue les performances
    - Fait des prédictions sur de nouvelles données
    """

    def __init__(self, processed_dir="data/processed", model_path="models/isolation_forest.pkl"):
        self.processed_dir = processed_dir
        self.model_path = model_path

    def load_processed(self, path=None):
        """Charge le dernier dataset prétraité"""
        if path:
            return pd.read_csv(path)
        else:
            files = [f for f in os.listdir(self.processed_dir) if f.endswith(".csv")]
            if not files:
                raise FileNotFoundError("Aucun fichier de données prétraitées trouvé.")
            files.sort()
            latest = os.path.join(self.processed_dir, files[-1])
            print(f"[INFO] Chargement du fichier : {latest}")
            return pd.read_csv(latest)

    def balance_smote(self, df):
        """Applique SMOTE pour équilibrer les classes"""
        if 'is_attack' not in df.columns:
            print(" Pas de colonne 'is_attack' — SMOTE non appliqué.")
            return df

        X = df.select_dtypes(include=['int64', 'float64']).drop(columns=['is_attack'], errors='ignore')
        y = df['is_attack']

        print(f"[INFO] Avant SMOTE : {y.value_counts().to_dict()}")

        smote = SMOTE(random_state=42)
        X_res, y_res = smote.fit_resample(X, y)

        # Afficher la distribution après SMOTE
        plt.figure(figsize=(5, 4))
        pd.Series(y_res).value_counts().plot(kind='bar', color=['#3498db', '#e74c3c'])
        plt.title("Distribution des classes après SMOTE")
        plt.xlabel("Classe (is_attack)")
        plt.ylabel("Nombre d'échantillons")
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        plt.tight_layout()
        plt.savefig("data/processed/smote_distribution.png")
        plt.close()

        print(f"[INFO] Après SMOTE : {pd.Series(y_res).value_counts().to_dict()}")
        print("[OK] Image sauvegardée : data/processed/smote_distribution.png")

        X_res['is_attack'] = y_res
        return X_res

    def train(self, path=None):
        """Entraîne Isolation Forest sur les données prétraitées"""
        df = self.load_processed(path)

        # Garder uniquement les données ayant un label (exclure celles de l’API Flutter)
        if 'is_attack' in df.columns:
            df = df[df['is_attack'].notna()]
        else:
            raise ValueError("La colonne 'is_attack' est obligatoire pour l'entraînement.")

        df = self.balance_smote(df)

        X = df.drop(columns=['is_attack'])
        y_true = df['is_attack']

        contamination = 0.05
        print(f"[INFO] Nombre de features : {len(X.columns)}")
        print(f"[INFO] Contamination utilisée : {contamination}")

        clf = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )
        clf.fit(X)

        # Sauvegarde du modèle
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(clf, self.model_path)
        print(f" Modèle IsolationForest sauvegardé dans : {self.model_path}")

        preds = clf.predict(X)
        preds = np.where(preds == -1, 1, 0)

        # Calcul des métriques
        acc = accuracy_score(y_true, preds)
        prec = precision_score(y_true, preds, zero_division=0)
        rec = recall_score(y_true, preds, zero_division=0)
        f1 = f1_score(y_true, preds, zero_division=0)
        cm = confusion_matrix(y_true, preds)

        metrics = {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "confusion_matrix": cm.tolist()
        }

        print("\n=== Rapport de performance ===")
        print(f"Accuracy   : {acc:.4f}")
        print(f"Precision  : {prec:.4f}")
        print(f"Recall     : {rec:.4f}")
        print(f"F1-score   : {f1:.4f}")
        print("Confusion Matrix :")
        print(cm)

        return clf, metrics

    def predict_df(self, df):
        """Prédit si une nouvelle donnée est une attaque (1) ou normale (0)"""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Modèle introuvable : {self.model_path}")

        clf = joblib.load(self.model_path)
        X = df.select_dtypes(include=['int64', 'float64']).copy()
        for col in ['is_attack', 'anomaly_score', 'is_attack_pred']:
            if col in X.columns:
                X = X.drop(columns=[col])

        # Harmoniser les features
        train_features = getattr(clf, 'feature_names_in_', None)
        if train_features is not None:
            X = X.reindex(columns=train_features, fill_value=0)

        preds = clf.predict(X)
        scores = clf.decision_function(X)

        df = df.copy()
        df["anomaly_score"] = scores
        df["is_attack_pred"] = np.where(preds == -1, 1, 0)

        print(f" Prédictions effectuées sur {len(df)} lignes.")
        return df
