
# -*- coding: utf-8 -*-
import os
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from xgboost import XGBClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    ConfusionMatrixDisplay,
    roc_auc_score
)
from imblearn.over_sampling import SMOTE


class DetectorXGB:
    """
    Détecteur basé sur XGBoost :
    - Entraîne un modèle supervisé sur les données prétraitées
    - Équilibre les classes via SMOTE
    - Évalue les performances (Accuracy, Precision, Recall, F1, ROC-AUC)
    - Prédit les attaques sur de nouvelles données
    """

    def __init__(self, processed_dir="data/processed", model_path="models/xgboost_detector.pkl"):
        self.processed_dir = processed_dir
        self.model_path = model_path

    # -------------------------------
    # 📂 Chargement du dataset
    # -------------------------------
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

    # -------------------------------
    # ⚖️ Équilibrage via SMOTE
    # -------------------------------
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

        print(f"[INFO] Apres SMOTE : {pd.Series(y_res).value_counts().to_dict()}")
        print("[OK] Image sauvegardee : data/processed/smote_distribution.png")

        X_res['is_attack'] = y_res
        return X_res

    # -------------------------------
    # 🧠 Entraînement du modèle
    # -------------------------------
    def train(self, path=None):
        """Entraîne XGBoost sur les données prétraitées"""
        df = self.load_processed(path)

        # Garder uniquement les données ayant un label (exclure celles de l’API Flutter)
        if 'is_attack' in df.columns:
            df = df[df['is_attack'].notna()]
        else:
            raise ValueError("La colonne 'is_attack' est obligatoire pour l'entraînement.")

        # Appliquer SMOTE
        df = self.balance_smote(df)

        X = df.drop(columns=['is_attack'])
        y = df['is_attack']

        print(f"[INFO] Entrainement sur {len(X)} échantillons et {len(X.columns)} features.")

        # Modèle XGBoost
        model = XGBClassifier(
            n_estimators=300,
            learning_rate=0.05,
            max_depth=6,
            subsample=0.8,
            colsample_bytree=0.8,
            scale_pos_weight=1,
            random_state=42,
            eval_metric='logloss'
        )

        model.fit(X, y)

        # Sauvegarde du modèle
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(model, self.model_path)
        print(f"[OK] Modèle XGBoost sauvegardé dans : {self.model_path}")

        # Évaluation sur le même dataset (ou mieux, split train/test)
        y_pred = model.predict(X)
        y_proba = model.predict_proba(X)[:, 1]

        acc = accuracy_score(y, y_pred)
        prec = precision_score(y, y_pred)
        rec = recall_score(y, y_pred)
        f1 = f1_score(y, y_pred)
        auc = roc_auc_score(y, y_proba)
        cm = confusion_matrix(y, y_pred)

        metrics = {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(auc, 4),
            "confusion_matrix": cm.tolist()
        }

        print("\n===  Rapport de performance XGBoost ===")
        print(f"Accuracy   : {acc:.4f}")
        print(f"Precision  : {prec:.4f}")
        print(f"Recall     : {rec:.4f}")
        print(f"F1-score   : {f1:.4f}")
        print(f"ROC-AUC    : {auc:.4f}")
        print("Confusion Matrix :")
        print(cm)

        # Afficher la matrice de confusion normalisée
        disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Normal", "Attack"])
        disp.plot(cmap="Blues")
        plt.title("Matrice de confusion - XGBoost")
        plt.savefig("data/processed/confusion_matrix_xgb.png")
        plt.close()

        print("[OK] Image sauvegardée : data/processed/confusion_matrix_xgb.png")

        return model, metrics

    # -------------------------------
    # 🔍 Prédiction sur nouveaux échantillons
    # -------------------------------
    def predict_df(self, df):
        """Prédit si une nouvelle donnée est une attaque (1) ou normale (0)"""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Modèle introuvable : {self.model_path}")

        model = joblib.load(self.model_path)
        X = df.select_dtypes(include=['int64', 'float64']).copy()
        for col in ['is_attack', 'anomaly_score', 'is_attack_pred']:
            if col in X.columns:
                X = X.drop(columns=[col])

        # Harmoniser les features
        train_features = getattr(model, 'feature_names_in_', None)
        if train_features is not None:
            X = X.reindex(columns=train_features, fill_value=0)

        preds = model.predict(X)
        proba = model.predict_proba(X)[:, 1]

        df = df.copy()
        df["attack_probability"] = proba
        df["is_attack_pred"] = preds

        print(f"[INFO] Predictions effectuees sur {len(df)} lignes.")
        return df
