from ecdsa import SigningKey, SECP256k1
from hashlib import sha256
import petlib.ecdsa
import petlib
import json

class TPM:
    def __init__(self, issuer):
        self.group = issuer.getGroup()
        self.order = issuer.getOrder()
        self.ipk = issuer.getPublicKey()
        self.generator = issuer.getGenerator()
        self.tsk = self.order.random()
        self.tpk = self.tsk * self.generator
        self.PCR = "0x4a5e81c41d4fbccb"
        self.attributes = {"Manufacturer ID":  "TCG",
                           "TPM Specification Version": "2.0",
                           "Device serial number": "ABC123456789",
                           "Time stamp": "20240501T075841Z",
                           "TPM Version": "2.0",
                           "Checksum": "e2939c36037fe2816dc7bf0fe0314c7c7bef7baada002cff4aacb76bc22a3e20"
                           }
        #self.comm = self.tsk * self.generator


    def generatePartialKey(self):
        self.partialSK = self.order.random()
        self.partialPK = self.partialSK * self.generator
 
    def getPublicKey(self):

        return self.tpk
    
    def getOrder(self):
        return self.order
    
    def getGroup(self):
        return self.group
    
    def getGenerator(self):
        return self.generator
    
    def challenge(self, elements):
        """Packages a challenge in a bijective way"""
        elem = [len(elements)] + elements
        elem_str = map(str, elem)
        elem_len = map(lambda x: "%s||%s" % (len(x) , x), elem_str)
        state = "|".join(elem_len)
        H = sha256()
        H.update(state.encode("utf8"))
        return H.digest()
    
    def prove(self):
        """Schnorr proof of the statement ZK(x ; h = g^x)"""
        assert self.tsk * self.generator == self.tpk
        w = self.getOrder().random()
        W = w * self.generator 

        state = ['schnorr', self.group.nid(), self.generator , self.tpk, W]
        hash_c = self.challenge(state)

        c = petlib.bn.Bn.from_binary(hash_c) % self.order
        r = (w - c * self.tsk) % self.order
        print("Host generate and send proof and partial Public key (k1 * g) to Issuer at tpm.prove\n")
        self.generatePartialKey()
        return ((c, r), self.partialPK)
    
    def saveCred(self,cred):
        self.cred = cred

    def getAttributes(self):
        return self.attributes
    
    def getPCR(self):
        return self.PCR
    
    def coSign(self, partialSignature, iPartialPK):
        print("Host receive partial signature (s2) and partial Public Key (R2 = k2 * g)and pass to TPM to produce joint signature at tpm.coSign")
        print("- TPM calcualte joint Key (R) with issuer partial Public key and host partial Secret key (R = k1 * k2 * g)")
        R = self.partialSK * iPartialPK# ie, k1 * k2 * g
        #print(type(self.partialSK), type(iPartialPK))
        #assert R_host == R
        rx, ry = R.get_affine()
        r = rx % self.order
    
        e = petlib.bn.Bn.from_binary(sha256(json.dumps(self.getAttributes()).encode()).digest())
        print("- TPM produce joint signature (r,s) where s = (k1^-1 * (m' + r * tsk) * s2) mod o using a modified ecdsa signature scheme with additional partial signature (commitment s2)")
        s = (self.partialSK.mod_inverse(self.order) * (e + r * self.tsk) * partialSignature)% self.order
        print("- TPM calculate joint Public Key Pair (Q_add = tpm public Key + issuer public Key, Q_mul = tpm secret Key * issuer public Key)")
        Q_add = self.getPublicKey() + self.ipk
        Q_mul = self.tsk * self.ipk
        
        #self check
        w = s.mod_inverse(self.order)
        u1 = (pow(e, 2) * w) % self.order
        u2 = (r*e * w) % self.order
        u3 = (pow(r, 2) * w) % self.order
        C = u1 * self.generator + u2 * Q_add + u3 * Q_mul
        cx, cy = C.get_affine()
        assert r == cx % self.order

        print("TPM pass joint signature and joint Public Pair to Host\n")
        return (r,s) , (Q_add, Q_mul)
    
    def sign(self, message):
        print("- TPM signs on PCR digest hash at tpm.sign\n")
        digest = sha256(message.encode()).digest()
        signature = petlib.ecdsa.do_ecdsa_sign(self.group,self.tsk,digest)

        assert(petlib.ecdsa.do_ecdsa_verify(self.group, self.tpk, signature, digest))
        return signature, message
    
    def saveJoint(self,jointSig):
        self.joint = jointSig