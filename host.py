import http.server
import socketserver
from hashlib import sha256
import petlib
class Host:
    def __init__(self, tpm):
        self.tpm = tpm
    
    def generateComm(self):
        self.comm = self.tpm.generateNewComm()
    
    def getPublicKey(self):
        return self.comm

    def getGroup(self):
        return self.tpm.getGroup()
    
    def getGenerator(self):
        return self.tpm.getGenerator()
    
    def getOrder(self):
        return self.tpm.getOrder()
    
    def prove(self):
        proof = self.tpm.prove()
        return proof, self.getAttributes()
    
    def getAttributes(self):
        return self.tpm.getAttributes()

    def getPCR(self):
        return self.tpm.getPCR()
    
    def saveCred(self, cred):
        self.cred = cred
        self.tpm.saveCred(cred)
    
    def sign(self, message):
        self.tpm.sign(message)

    def coSign(self):
        return self.tpm.coSign()

    def saveJoint(self, jointSig):
        self.tpm.saveJoint(jointSig)
        self.joint = jointSig