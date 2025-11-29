class Reactor:

    def __init__(self):
        pass

    def react(self, prediction_df):

        print("\n=== RÉACTEUR : ANALYSE DE SÉCURITÉ ===")

        for _, row in prediction_df.iterrows():

            prob = row["attack_probability"]

            print("\n--- Résultat ---")
            print(f"Probabilité d'attaque : {round(prob, 3)}")

            # MENACE CRITIQUE
            if prob > 0.75:
                print(" ATTACK CRITIQUE")
                print(" Action : Blocage immédiat de l'IP")

            # MFA OBLIGATOIRE
            elif 0.4 <= prob <= 0.75:
                print("RISQUE MODÉRÉ")
                print("Action : Authentification forte (MFA)")

            # CAS NORMAL
            else:
                print(" TRAFIC NORMAL")
                print(" Aucune action requise")
