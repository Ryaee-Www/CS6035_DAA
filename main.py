if __name__ == '__main__':
    from issuer import Issuer
    from host import Host
    from verifier import Verifier

    # Create an issuer
    issuer = Issuer()

    # The issuer issues a new private key to a host
    host = Host(issuer)

    # The host creates an attestation
    message = b"Hello, World!"  # The message to be signed
    signature = host.attest(message)

    # A verifier verifies the attestation
    verifier = Verifier(issuer.verifying_key)

    # Verify the signature
    is_valid = host.verifying_key.verify(signature, message)

    print(f"Signature valid: {is_valid}")