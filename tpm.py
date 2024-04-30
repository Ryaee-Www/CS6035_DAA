from ecdsa import SigningKey, SECP256k1
from hashlib import sha256
import petlib
import json

class TPM:
    def __init__(self, issuer):
        self.group = issuer.getGroup()
        self.order = issuer.getOrder()
        self.generator = issuer.getGenerator()
        tsk = self.order.random()
        self.PCR = "0x4a5e81c41d4fbccb"
        self.attributes = {}
        #self.comm = self.tsk * self.generator
        self.tsk = tsk

    def generateNewComm(self):
        self.comm = self.tsk * self.generator#TODO check if generator reuseable
        return self.comm
    
    def getOrder(self):
        return self.order

    def getComm(self):
        return self.comm
    
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
        assert self.tsk * self.generator == self.comm
        w = self.getOrder().random()
        W = w * self.generator 

        state = ['schnorr', self.group.nid(), self.generator , self.comm, W]
        hash_c = self.challenge(state)

        c = petlib.bn.Bn.from_binary(hash_c) % self.order
        r = (w - c * self.tsk) % self.order
        print("generate and send proof to Issuer")
        return (c, r)
    
    def saveCred(self,cred):
        self.cred = cred

    def getAttributes(self):
        return self.attributes
    
    def getPCR(self):
        return self.PCR
    
    def coSign(self):
        psig1 = self.cred
        psig2,digest = self.sign(self.getAttributes())
        Rs, Ss = zip(*[psig1,psig2])
        sumR = sum(Rs)
        sumS = sum(Ss)

        return (sumR, sumS % (self.order)), digest
    
    def sign(self, message):
        digest = sha256(json.dumps(message).encode()).digest()
        signature = petlib.ecdsa.do_ecdsa_sign(self.group,self.tsk,digest)
        return signature, digest
    
    def saveJoint(self,jointSig):
        self.joint = jointSig