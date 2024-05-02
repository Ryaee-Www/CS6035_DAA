# DAA
Direct Anonymous Attestation project for cs6035 @ Georgia Tech
This project require petlib, which runs on a ubuntu linux machine.

you can install petlib with:

> pip install petlib

document and additional install instruction can be found at:https://petlib.readthedocs.io/en/latest/

running the program: running main.py directly using
>python main.py

This project is developed and implemented on python 3.9 with ubuntu linux device. But all python version > 3.6 on linux-like device should work.

The project implements a DAA scheme. There are 4 actors:
Host, tpm, issuer, verifier.
Host represent the user; tpm represents the trusted platform module in Host's device; issuer represents manufacture of tpm; verifier represent end parties like bank, shop, merchant, service provide, server storage, etc that Host is trying to access.

Assumptions: Tpm is the only trustable components on user's device. Only TPM has tsk. param = (tpk, ipk, G, g, order) are widely known to are parites.

The process starts at Host sending schnorr proof to issuer to prove it has a valid tpm private key. Together with the proof is partial signature Public key R1 and it's tpm attributes.
Issuer receive schorr proof, reproduce challenge and verify issuer's proof of knowledge. It then verify received TPM attributs. If attributs checks out, it generate a partial signature s2 using k2, and issuer secret key x2. It return R2 = k2*g, s2 to Host.
Host signs joint signature using partial secret key k1 ,partial signature s2 and tpm secret key x1 to produce joint(r,s), it also calculate joint signature public key pair Qadd = ipk + tpk and Qmul = isk * tsk * g. It signs on PCR using x1, and send (r,s), (Qadd, Qmul), attribute hash digest, PCR signature and PCR to verifier.
Verifier verify (r,s) using (Qadd, Qmul) and attribute hash digest, verify PCR signature using tpk and PCR. Finally it verify if PCR value is in its PCR value library. If all checksout, it procceed to provide service to Host.
