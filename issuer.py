from ecdsa import SigningKey, VerifyingKey, SECP256k1


class Issuer:
    def __init__(self):
        self.signing_key = SigningKey.generate(curve=SECP256k1)  # Generate a new ECDSA key pair
        self.verifying_key = self.signing_key.get_verifying_key()

    def issue(self):
        # Issue a private key to a host (in reality this should preferably be done securely)
        host_signing_key = SigningKey.generate(curve=SECP256k1)
        return host_signing_key, host_signing_key.get_verifying_key()