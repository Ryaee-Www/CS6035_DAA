import http.server
import socketserver
from hashlib import sha256
import petlib
class Host:
    def __init__(self, tpm):
        self.tpm = tpm
    
    def generateComm(self):
        self.comm = self.tpm.generatePartialKey()
    
    def getPublicKey(self):
        return self.tpm.getPublicKey()

    def getGroup(self):
        return self.tpm.getGroup()
    
    def getGenerator(self):
        return self.tpm.getGenerator()
    
    def getOrder(self):
        return self.tpm.getOrder()
    
    def prove(self):
        proof, partialPublicKey = self.tpm.prove()
        return proof, partialPublicKey, self.getAttributes()
    
    def getAttributes(self):
        return self.tpm.getAttributes()

    def getPCR(self):
        return self.tpm.getPCR()
    
    def saveCred(self, cred):
        self.cred = cred
        self.tpm.saveCred(cred)
    
    def sign(self, message):
        return self.tpm.sign(message)

    def coSign(self):
        return self.tpm.coSign(*self.cred)

    def saveJoint(self, jointSig):
        print("Host and TPM save joint Signature and joint Key")
        self.tpm.saveJoint(jointSig)
        self.joint = jointSig
        