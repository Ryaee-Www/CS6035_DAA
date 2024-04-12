from ecdsa import SigningKey, SECP256k1


class Issuer:
    def __init__(self):
        self.ek = SigningKey.generate(curve=SECP256k1)  # Generate a new ECDSA key pair
        self.aik = self.ek.get_verifying_key()

    def issue(self):
        # Issue a private key to a host (in reality this should preferably be done securely)
        return self.ek, self.aik
