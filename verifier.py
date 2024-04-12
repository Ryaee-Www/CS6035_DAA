class Verifier:
    def __init__(self, issuer_aik):
        self.issuer_verifying_aik = issuer_aik

    def verify(self, signature, message, tpm_aik):
        # Verify an attestation
        return tpm_aik.verify(signature, message) and self.issuer_verifying_aik.verify(signature, message)
