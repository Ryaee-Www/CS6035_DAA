from ecdsa import SigningKey, SECP256k1
import petlib
from petlib.ec import EcGroup, EcPt
from hashlib import sha256
import json
import petlib.ecdsa

class Issuer:
    def __init__(self, EC):
        self.EC = EC
        self.group = EcGroup(self.EC)
        self.generator = self.group.generator()
        self.order = self.group.order()
        self.isk = self.order.random()
        self.param = self.isk * self.generator
  
        #self.ek = SigningKey.generate(curve=SECP256k1)  # Generate a new ECDSA key pair
        #self.aik = self.ek.get_verifying_key()
    
    def getGroup(self):
        return self.group
    
    def getGenerator(self):
        return self.generator
    
    def getOrder(self):
        return self.order
    
    def getPublicKey(self):
        return self.param
    
    def challenge(self, elements):
        """Packages a challenge in a bijective way"""
        elem = [len(elements)] + elements
        elem_str = map(str, elem)
        elem_len = map(lambda x: "%s||%s" % (len(x) , x), elem_str)
        state = "|".join(elem_len)
        H = sha256()
        H.update(state.encode("utf8"))
        return H.digest()
    
    def verify(self,proof, hPublicK):
        """Verify the statement ZK(x ; h = g^x)"""
        c, r = proof
        W = (r * self.getGenerator() + c * hPublicK)

        state = ['schnorr', self.getGroup().nid(), self.getGenerator(), hPublicK, W]
        hash_c = self.challenge(state)
        c2 = petlib.bn.Bn.from_binary(hash_c) % self.getOrder()
        return c == c2
    
    def produceCred(self, hostAttributes):
        digest = sha256(json.dumps(hostAttributes).encode()).digest()
        partialSignature = petlib.ecdsa.do_ecdsa_sign(self.getGroup(),self.isk,digest)
        return partialSignature