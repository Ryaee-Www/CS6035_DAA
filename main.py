from host import Host
from issuer import Issuer
from tpm import TPM
from verifier import Verifier

if __name__ == '__main__':

    # Create an issuer
    issuer = Issuer()

    # The issuer issues a new private key to a host
    tpm = TPM(issuer)

    # The host creates an attestation
    message = b"Hello, World!"  # The message to be signed
    signature = tpm.attest(message)

    # A verifier verifies the attestation
    verifier = Verifier(issuer.aik)

    # Verify the signature
    is_valid = verifier.verify(signature, message, issuer.aik)
    print(f"Signature valid: {is_valid}")
