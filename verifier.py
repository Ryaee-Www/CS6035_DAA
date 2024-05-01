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
        print("verifier verify joint signature (r,s) by key (Q_add, Q_mul) at verifier.verifyJoint")
        
        sig, key = joint
        r, s = sig
        Q_add, Q_mul = key
        print("- verifier calculate w = s ^ -1 mod o")
        w = s.mod_inverse(self.order)

        e = petlib.bn.Bn.from_binary(digest)

        print("- verifier calculate u1 = e ^ 2 * w mod o")
        u1 = (pow(e, 2) * w) % self.order
        print("- verifier calculate u2 = e * r * w mod o")
        u2 = (r*e * w) % self.order
        print("- verifier calculate u3 = r ^ 2 * w mod o")
        u3 = (pow(r, 2) * w) % self.order
        print("- verifier calculate C = u1 * g + u2 * Q_add + u3 * Q_mul")
        C = u1 * self.generator + u2 * Q_add + u3 * Q_mul
        cx, cy = C.get_affine()
        #print(r,cx % self.order )
        print("- verifier check if C[0] mod o = r")
        if r == cx % self.order:
            print("joint signature verified.\n")
        else:
            print("joint signature is not valid.\n")
        return r == cx % self.order
    
    def verifyPCR(self, proof):
        print("verifier verify PCR signature (r,s) by key hpk at verifier.verifyPCR")
        sig, PCRmsg = proof
        print("- verifier calculate PCR message's hash digest")
        digest = sha256(PCRmsg.encode()).digest()
        print("- verifier check tpm signature on PCR message")
        if petlib.ecdsa.do_ecdsa_verify(self.group,self.hpk, sig, digest):
            print("\t*host signature on PCR is valid.")
            print("- verifier if PCR message is in it's secured PCR hash library")
            if (PCRmsg in self.securePCR):
                print("Host PCR value shows host's device is secure.\n")
                return True
            else:
                print("Host PCR value show host's device is not secure")
                return False
        else:
            print("host signature on PCR is invalid. Aborts.")
            return False