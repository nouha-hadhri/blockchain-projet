import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class Reactor:

    def __init__(self, email_from, email_password, email_to):
        self.email_from = email_from
        self.email_password = email_password
        self.email_to = email_to

    def send_alert_email(self, row):
        ip = row.get("source_ip", "non-disponible")
        ua = row.get("user_agent", "non-disponible")
        attempts = row.get("attempts", "N/A")
        prob = round(row["attack_probability"], 3)

        subject = " Alerte Sécurité — Attaque détectée"
        body = (
            f"Une activité suspecte vient d'être détectée \n\n"
            f" Détails :\n"
            f"- IP source : {ip}\n"
            f"- Probabilité d'attaque : {prob}\n"
            f"- User-Agent : {ua}\n"
            f"- Nombre de tentatives : {attempts}\n\n"
            f"Veuillez vérifier immédiatement."
        )

        msg = MIMEMultipart()
        msg["From"] = self.email_from
        msg["To"] = self.email_to
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        try:
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(self.email_from, self.email_password)
            server.sendmail(self.email_from, self.email_to, msg.as_string())
            server.quit()

            print(" Alerte envoyée avec succès.")
        except Exception as e:
            print(" Erreur lors de l'envoi du mail :", e)


    def react(self, prediction_df):

        print("\n=== RÉACTEUR : ANALYSE DE SÉCURITÉ ===")

        for _, row in prediction_df.iterrows():

            prob = row["attack_probability"]
            print("\n--- Résultat ---")
            print(f"Probabilité d'attaque : {round(prob, 3)}")

            #  MENACE CRITIQUE
            if prob > 0.75:
                print(" ATTACK CRITIQUE")
                print(" Action : Envoi d’un mail d’alerte")
                self.send_alert_email(row)

            #  RISQUE MODÉRÉ
            elif 0.4 <= prob <= 0.75:
                print(" RISQUE MODÉRÉ")
                print(" Action : MFA recommandé")

            # 🟢 NORMAL
            else:
                print(" TRAFIC NORMAL")
                print("→ Aucune action requise")
