from host import Host
from issuer import Issuer
from tpm import TPM
from verifier import Verifier
import petlib
from hashlib import sha256
class secrityParam():
    def __init__(self, group, generator, order, hpk, ipk):
        self.ECGroup = group
        self.generator = generator
        self.order = order
        self.hpk = hpk
        self.ipk = ipk
def doJoin(host, issuer):
    #join t, host generate public key from tpm private key.
    host.generateComm()
    #join i, host prove to issuer that it has valid tpm, issuer issue crediential using its private key on host message's hash digest
    proof, hostAttributes = host.prove()
    condition = issuer.verify(proof,host.getPublicKey())
    print(condition)
    if condition:
        cred = issuer.produceCred(hostAttributes)
        host.saveCred(cred)
        

    
def doSign(host):
    PCR = host.getPCR()
    host.saveJoint(host.coSign())
    #print("joint", host.joint)
    return host.joint, host.sign(PCR)


def doVerify(verifier, host, message):
    print(verifier.verifyJoint(host.getGenerator(), host.getPublicKey(), *host.joint, host))
    #return verifier.verifyJoint(host.getGroup(), host.getPublicKey(), *host.joint)

if __name__ == '__main__':
    
    ##SETUP PHASE

    # Create an issuer
    issuer = Issuer(713)

    # The issuer issues a new private key to a host
    tpm = TPM(issuer)
    host = Host(tpm)
    verifier = Verifier(issuer)
    #param = secrityParam(issuer.getGroup(), issuer.getGenerator(), issuer.getOrder(),host.getPublicKey(), issuer.getPublicKey())
    #

    ##JOIN PHASE

    doJoin(host,issuer)
    
    
    ##SIGN PHASE
    proofToVerifier = doSign(host)
    
    ##VERIFY PHASE
    acceptance = doVerify(verifier, host, proofToVerifier)
    '''
    # The host creates an attestation
    message = b"Hello, World!"  # The message to be signed
    signature = tpm.attest(message)

    # A verifier verifies the attestation
    

    # Verify the signature
    is_valid = verifier.verify(signature, message, issuer.aik)
    print(f"Signature valid: {is_valid}")
    '''