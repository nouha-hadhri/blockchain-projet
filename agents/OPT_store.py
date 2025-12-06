class OTPStore:
    _store = {}

    @staticmethod
    def save(email, otp):
        OTPStore._store[email] = otp

    @staticmethod
    def verify(email, code):
        return OTPStore._store.get(email) == code
