import http.server
import socketserver
class Host:
    def __init__(self, issuer):
        self.ek, self.aik = issuer.issue()

    def attest(self, message):
        # Create an attestation
        signature = self.ek.sign(message)
        return signature