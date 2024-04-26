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

    def prove(self):
        proof = self.tpm.prove()
        return proof