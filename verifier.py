import http.server
import socketserver
import petlib
class Verifier:
    def __init__(self, issuer):
        #self.secrityParam = secrityParam
        self.ipk = issuer.getPublicKey()

    def verifyJoint(self, g, tpk, sig, digest, host):
        assert tpk is host.getPublicKey()
        assert sig is host.joint[0]
        assert digest is host.joint[1]
        # Verify an attestation
        pk = tpk + self.ipk
        r,s = sig
        n = host.getOrder()
        e = digest
        S_inv = pow(s, -1, n)
        u1 = petlib.bn.Bn.from_binary(e) * S_inv % n
        print(u1)
        print(host.getOrder())
        print(r)
        print(pk)
        print(host.getOrder())
        u2 = r * S_inv % n
        R_prime = host.getOrder() * u1 + pk*u2
        return R_prime[0] == r
