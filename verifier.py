import http.server
import socketserver
import petlib
from hashlib import sha256
import json

import petlib.ecdsa
class Verifier:
    def __init__(self, param):
        #self.secrityParam = secrityParam
        self.group = param.ECGroup
        self.generator = param.generator
        self.order = param.order
        self.ipk = param.ipk
        self.hpk = param.hpk

        self.securePCR = ["0x4a5e81c41d4fbccb"]

    def verifyJoint(self,joint, digest):
        sig, key = joint
        r, s = sig
        Q_add, Q_mul = key
        w = s.mod_inverse(self.order)

        e = petlib.bn.Bn.from_binary(digest)

        
        u1 = (pow(e, 2) * w) % self.order
        u2 = (r*e * w) % self.order
        u3 = (pow(r, 2) * w) % self.order
        C = u1 * self.generator + u2 * Q_add + u3 * Q_mul
        cx, cy = C.get_affine()
        #print(r,cx % self.order )
        if r == cx % self.order:
            print("joint signature verified.\n")
        else:
            print("joint signature is not valid.")
        return r == cx % self.order
    
    def verifyPCR(self, proof):
        sig, PCR = proof


        if petlib.ecdsa.do_ecdsa_verify(self.group,self.hpk, sig, PCR):
            print("host signature on PCR is valid.")
        else:
            print("host signature on PCR is invalid")
        return PCR in self.securePCR