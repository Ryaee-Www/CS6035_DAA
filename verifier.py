class Verifier:
    def __init__(self, issuer_verifying_key):
        self.issuer_verifying_key = issuer_verifying_key

    def verify(self, signature, message, host_verifying_key):
        # Verify an attestation
        return host_verifying_key.verify(signature, message) and self.issuer_verifying_key.verify(signature, message)