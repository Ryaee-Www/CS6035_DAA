from ecdsa import SigningKey, SECP256k1


class TPM:
    def __init__(self, issuer):
        self.ek, self.aik = issuer.issue()

    def attest(self, message):
        # Create an attestation
        signature = self.ek.sign(message)
        return signature
