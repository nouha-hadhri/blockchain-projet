import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class EmailMFA:

    @staticmethod
    def generate_otp():
        """Génère automatiquement un code OTP sécurisé à 6 chiffres"""
        return str(random.randint(100000, 999999))

    @staticmethod
    def send_email(to_email, otp, email_from, email_password):
        subject = "Votre Code MFA"
        body = f"Votre code MFA est : {otp}\n\nNe le partagez jamais."

        msg = MIMEMultipart()
        msg["From"] = email_from
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        try:
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(email_from, email_password)
            server.sendmail(email_from, to_email, msg.as_string())
            server.quit()

            print(f"[EMAIL] OTP envoyé à {to_email}")
            return True

        except Exception as e:
            print("[ERREUR ENVOI EMAIL] :", e)
            return False
