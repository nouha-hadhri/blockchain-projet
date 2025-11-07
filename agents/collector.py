import pandas as pd
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import os
import joblib

class DataCollector:
    def __init__(self, input_path, output_dir="data/processed", scaler_path="models/scaler.pkl"):
        self.input_path = input_path
        self.output_dir = os.path.abspath(output_dir)
        self.scaler = StandardScaler()
        self.scaler_path = scaler_path
        self.output_file = os.path.join(self.output_dir, "processed_data.csv")

    def load_data(self):
        print(f"Chargement des donnees depuis : {self.input_path}")

        # Charger le dataset
        if self.input_path.endswith(".xlsx"):
            df = pd.read_excel(self.input_path, engine="openpyxl")
        else:
            df = pd.read_csv(self.input_path)

        print(f" Dataset charge : {df.shape[0]} lignes, {df.shape[1]} colonnes")

        # Nettoyage et préparation
        df = df.drop_duplicates()
        df.drop(columns=["id"], inplace=True, errors="ignore")

        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df = df.dropna(subset=["timestamp"])
        df["hour"] = df["timestamp"].dt.hour
        df["day_of_week"] = df["timestamp"].dt.dayofweek
        df.drop(columns=["timestamp"], inplace=True)

        # Colonne indicative (optionnelle)
        df["is_bot"] = df["user_agent"].str.contains(
            "bot|curl|python|scanner", case=False, na=False
        ).astype(int)

        # Nettoyage colonnes inutiles
        df.drop(columns=["user_agent", "source_ip"], inplace=True, errors="ignore")
        df = pd.get_dummies(df, columns=["geo"], drop_first=True)

        # Normalisation
        cols_to_scale = ["response_time_ms", "attempts"]
        df[cols_to_scale] = self.scaler.fit_transform(df[cols_to_scale])

        # Sauvegarde du scaler pour usage futur (API)
        os.makedirs(os.path.dirname(self.scaler_path), exist_ok=True)
        joblib.dump(self.scaler, self.scaler_path)

        # Sauvegarde du dataset prétraité
        os.makedirs(self.output_dir, exist_ok=True)
        df.to_csv(self.output_file, index=False)
        print(f" Donnees pretraitees sauvegardees dans : {self.output_file}\n")

        # === 📊 Affichage de la distribution des classes (is_attack) ===
        if "is_attack" in df.columns:
            print("Distribution des classes (is_attack) :")
            print(df["is_attack"].value_counts(normalize=False))
            print("\nRepartition en pourcentage :")
            print((df["is_attack"].value_counts(normalize=True) * 100).round(2))
            print("-----------------------------------------------------\n")

            # Création du graphique
            counts = df["is_attack"].value_counts()
            plt.figure(figsize=(5, 4))
            plt.bar(counts.index.astype(str), counts.values, color=["#4CAF50", "#F44336"])
            plt.title("Distribution des classes (is_attack)")
            plt.xlabel("Classe (0 = normal, 1 = attaque)")
            plt.ylabel("Nombre d'occurrences")
            plt.grid(axis="y", linestyle="--", alpha=0.6)

            # Sauvegarde de l’image
            img_path = os.path.join(self.output_dir, "class_distribution.png")
            plt.tight_layout()
            plt.savefig(img_path)
            plt.close()
            print(f" Graphique de distribution sauvegarde dans : {img_path}\n")
        else:
            print(" Aucune colonne 'is_attack' détectée pour afficher la distribution.\n")

        return df

    def preprocess_single(self, new_data: dict):
        """Prétraiter une seule ligne reçue via API Flutter (non labellisée)"""
        df = pd.DataFrame([new_data])

        # Prétraitement similaire
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df = df.dropna(subset=["timestamp"])

        df["hour"] = df["timestamp"].dt.hour
        df["day_of_week"] = df["timestamp"].dt.dayofweek
        df.drop(columns=["timestamp"], inplace=True)

        df["is_bot"] = df["user_agent"].str.contains(
            "bot|curl|python|scanner", case=False, na=False
        ).astype(int)
        df.drop(columns=["user_agent", "source_ip"], inplace=True, errors="ignore")

        # Encodage geo
        df = pd.get_dummies(df, columns=["geo"], drop_first=True)

        # Alignement avec le dataset principal
        if os.path.exists(self.output_file):
            old_df = pd.read_csv(self.output_file)
            for col in old_df.columns:
                if col not in df.columns:
                    df[col] = 0
            # Exclure le label is_attack pour la donnée API
            if "is_attack" in df.columns:
                df.drop(columns=["is_attack"], inplace=True)
            df = df[old_df.drop(columns=["is_attack"], errors="ignore").columns]
        else:
            print(" Aucun dataset existant trouve, la nouvelle donnée sera initialisee seule.")

        # ⚙️ Normalisation avec le scaler existant (pas de refit)
        if os.path.exists(self.scaler_path):
            scaler = joblib.load(self.scaler_path)
            cols_to_scale = ["response_time_ms", "attempts"]
            df[cols_to_scale] = scaler.transform(df[cols_to_scale])
        else:
            print(" Aucun scaler trouve, les valeurs ne seront pas normalisées.")

        return df

    def add_new_data(self, new_data: dict):
        """Ajoute une nouvelle donnée prétraitée au dataset existant"""
        new_df = self.preprocess_single(new_data)

        if os.path.exists(self.output_file):
            df_existing = pd.read_csv(self.output_file)
            updated_df = pd.concat([df_existing, new_df], ignore_index=True)
        else:
            updated_df = new_df

        updated_df.to_csv(self.output_file, index=False, encoding="utf-8")
        print(f" Nouvelle donnee ajoutee a : {self.output_file}")
        print(f"Taille actuelle du dataset : {updated_df.shape[0]} lignes")

        return updated_df
