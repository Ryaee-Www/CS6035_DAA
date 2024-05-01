from host import Host
from issuer import Issuer
from tpm import TPM
from verifier import Verifier
import petlib
from hashlib import sha256
import json
class secrityParam():
    def __init__(self, group, generator, order, ipk, hpk):
        self.ECGroup = group
        self.generator = generator
        self.order = order
        self.ipk = ipk
        self.hpk = hpk
    def printAll(self):
        print("param:", self.ECGroup, self.generator, self.order, self.ipk, self.hpk)
    
def doJoin_t(host):
    #join t, host generate public key from tpm private key.
    host.generateComm()
    return host.getPublicKey()

def doJoin_i(host, issuer):
    
    #join i, host prove to issuer that it has valid tpm, issuer issue crediential using its private key on host message's hash digest
    proof, partialPublicKey, hostAttributes = host.prove()
    condition = issuer.verify(proof,host.getPublicKey())
    #print(condition)
    if condition:
        cred = issuer.produceCred(hostAttributes, partialPublicKey)
        host.saveCred(cred)
        

    
def doSign(host):
    PCR = host.getPCR()
    host.saveJoint(host.coSign())
    print("Host sign (with help of TPM) on a PCR digest, send the joint signature, joint key, host attribute's hash Digest, host's tpm signature on PCR value and PCR value to verifier")
    attributeDigest = sha256(json.dumps(host.getAttributes()).encode()).digest()
    #print("joint", host.joint)
    return host.joint, attributeDigest, host.sign(PCR)


def doVerify(verifier, proofToVerifier):
    print("Verifier receive host's joint signature, joint key, attribute digest, pcrSig and pcr value")
    joint, digest, sigPCR= proofToVerifier

    if verifier.verifyJoint(joint, digest):
        return verifier.verifyPCR(sigPCR)
    
    #verifier.verifyPCR()
    #print()
    #return verifier.verifyJoint(host.getGroup(), host.getPublicKey(), *host.joint)

if __name__ == '__main__':
    print("*Assume procedure start at host - issuer interation*\n")
    ##SETUP PHASE

    # Create an issuer
    issuer = Issuer(713)

    # The issuer issues a new private key to a host
    tpm = TPM(issuer)
    host = Host(tpm)
    host.getPublicKey()
    tpm.getPublicKey()
    
    param = secrityParam(*issuer.getParam(), host.getPublicKey())

    verifier = Verifier(param)
    #param = secrityParam(issuer.getGroup(), issuer.getGenerator(), issuer.getOrder(),host.getPublicKey(), issuer.getPublicKey())
    #

    ##JOIN PHASE
    doJoin_t(host)
    doJoin_i(host,issuer)
    
    
    ##SIGN PHASE
    proofToVerifier = doSign(host)
    host.getPublicKey()
    ##VERIFY PHASE
    accept = doVerify(verifier, proofToVerifier)
    if accept:
        print("DAA procedure ends. Host is proven to be valid. Verifier procced to offer service/resource to Host.")
    '''
    # The host creates an attestation
    message = b"Hello, World!"  # The message to be signed
    signature = tpm.attest(message)

    # A verifier verifies the attestation
    

    # Verify the signature
    is_valid = verifier.verify(signature, message, issuer.aik)
    print(f"Signature valid: {is_valid}")
    '''