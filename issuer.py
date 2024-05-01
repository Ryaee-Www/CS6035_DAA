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
        self.ipk = self.isk * self.generator
  
        #self.ek = SigningKey.generate(curve=SECP256k1)  # Generate a new ECDSA key pair
        #self.aik = self.ek.get_verifying_key()
    
    def getGroup(self):
        return self.group
    
    def getGenerator(self):
        return self.generator
    
    def getOrder(self):
        return self.order
    
    def getPublicKey(self):
        return self.ipk
    
    def getParam(self):
        return self.getGroup(), self.getGenerator(), self.getOrder(), self.getPublicKey()
    
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
        print("Issuer receive host's Schnorr Proof of knowledge of its private key at issuer.verify\n")
        c, r = proof
        W = (r * self.getGenerator() + c * hPublicK)

        state = ['schnorr', self.getGroup().nid(), self.getGenerator(), hPublicK, W]
        hash_c = self.challenge(state)
        c2 = petlib.bn.Bn.from_binary(hash_c) % self.getOrder()
        if c == c2:
            print("Hashes equals, Host tpm private key validated.\n")
            print("Issuer check Host Attributes:")
            print("- Check host tpm Specifications...")
            print("- Check tpm checksum...\n")
            print("Check Complete. Host validated\n")
            return True
        else:
            print("Host tpm private key not valid. Aborts.")
            return False

    
    def produceCred(self, hostAttributes, hostPartialPk):
        print("Issuer Generate partical signature at issuer.produceCred")
        
        digest = sha256(json.dumps(hostAttributes).encode()).digest()
        e = petlib.bn.Bn.from_binary(digest)
        partialSk = self.order.random()
        partialPk = partialSk * self.generator
        print("- Issuer calcuate joint Key with host paritial Public key and issuer partial Secret Key (k2 * k1 * g)")
        jointKey = partialSk * hostPartialPk #k1 * k2 * g -- ie, host ecdsa secret * issuer ecdsa secret * generator
        
        rx, ry = jointKey.get_affine()
        
        r = rx % self.order
        print("- Issuer produce Partial signature (commitment s2) using paritial secret key and issuer secret key.\n- Sign on host Attribute's hash digest to produce an ecdsa partial signature (s2)")
        partialSignature = (partialSk.mod_inverse(self.order) * (e + r * self.isk)) % self.order
        print("Issuer send partial signature (commitment s2) and partial Public Key to host.\n")
        return partialSignature, partialPk