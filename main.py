from host import Host
from issuer import Issuer
from tpm import TPM
from verifier import Verifier
import petlib
from hashlib import sha256

def doJoin(host, issuer):
    host.generateComm()
    proof = host.prove()
    condition = issuer.verify(proof,host.getPublicKey())
    print(condition)

def challenge(elements):
    """Packages a challenge in a bijective way"""
    elem = [len(elements)] + elements
    elem_str = map(str, elem)
    elem_len = map(lambda x: "%s||%s" % (len(x) , x), elem_str)
    state = "|".join(elem_len)
    H = sha256()
    H.update(state.encode("utf8"))
    return H.digest()

if __name__ == '__main__':
    
    ##SETUP PHASE

    # Create an issuer
    issuer = Issuer(713)

    # The issuer issues a new private key to a host
    tpm = TPM(issuer)
    host = Host(tpm)
    verifier = Verifier(issuer)

    ##JOIN PHASE
    #JOIN_T
    doJoin(host,issuer)

    #JOIN_I


    # The host creates an attestation
    message = b"Hello, World!"  # The message to be signed
    signature = tpm.attest(message)

    # A verifier verifies the attestation
    

    # Verify the signature
    is_valid = verifier.verify(signature, message, issuer.aik)
    print(f"Signature valid: {is_valid}")
