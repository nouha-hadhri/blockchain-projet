from .OPT_store import OTPStore
from .email_MFA import EmailMFA

class SecurityActions:

    @staticmethod
    def trigger_mfa_email(row, email_from, email_password):
        # Email statique pour MFA
        to_email = "nouha.hadhri@enis.tn"

        otp = EmailMFA.generate_otp()
        sent = EmailMFA.send_email(to_email, otp, email_from, email_password)

        if sent:
            OTPStore.save(to_email, otp)
            print("OTP généré automatiquement et envoyé à", to_email)
            return True

        print("Erreur lors de l'envoi du mail")
        return False

    @staticmethod
    def verify_mfa_email(email, code):
        if OTPStore.verify(email, code):
            print("MFA validé ✔️")
            return True
        else:
            print("Code MFA invalide ❌")
            return False
