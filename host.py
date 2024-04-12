import http.server
import socketserver
class Host:
    def __init__(self, issuer):
        self.signing_key, self.verifying_key = issuer.issue()

    def attest(self, message):
        # Create an attestation
        signature = self.signing_key.sign(message)
        return signature