from ecdsa import SigningKey, VerifyingKey, SECP256k1
import http.server
import socketserver
class Issuer:
    def __init__(self):
        self.signing_key = SigningKey.generate(curve=SECP256k1)  # Generate a new ECDSA key pair
        self.verifying_key = self.signing_key.get_verifying_key()

    def issue(self):
        # Issue a private key to a host (in reality this should preferably be done securely)
        host_signing_key = SigningKey.generate(curve=SECP256k1)
        return host_signing_key, host_signing_key.get_verifying_key()


if __name__ == '__main__':


    # Create an issuer
    issuer = Issuer()

    # The host creates an attestation
    message = b"Hello, World!"  # The message to be signed
    signature = host.attest(message)

    # A verifier verifies the attestation
    verifier = Verifier(issuer.verifying_key)

    # Verify the signature
    is_valid = host.verifying_key.verify(signature, message)

    print(f"Signature valid: {is_valid}")