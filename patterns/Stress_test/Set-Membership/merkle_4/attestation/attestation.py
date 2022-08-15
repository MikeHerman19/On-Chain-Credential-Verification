import hashlib
from zokrates_pycrypto.eddsa import PrivateKey, PublicKey
from zokrates_pycrypto.field import FQ
from zokrates_pycrypto.utils import write_signature_for_zokrates_cli
import struct
import sys

def write_signature_for_zokrates_cli(pk, sig, msg):
    "Writes the input arguments for verifyEddsa in the ZoKrates stdlib to file."
    sig_R, sig_S = sig
    args = [sig_R.x, sig_R.y, sig_S, pk.p.x.n, pk.p.y.n]
    args = " ".join(map(str, args))
    M0 = msg.hex()[:64]
    M1 = msg.hex()[64:]
    b0 = [str(int(M0[i:i+8], 16)) for i in range(0,len(M0), 8)]
    b1 = [str(int(M1[i:i+8], 16)) for i in range(0,len(M1), 8)]
    args = args + " " + " ".join(b0 + b1)
    return args

def zok_hash(lhs, rhs):
    preimage = int.to_bytes(lhs, 32, "big") + int.to_bytes(rhs, 32, "big")

    return hashlib.sha256(preimage).digest() 

def zok_out_u32(val):
    M0 = val.hex()[:64]
    M1 = val.hex()[64:]
    b0 = [str(int(M0[i:i+8], 16)) for i in range(0,len(M0), 8)]
    b1 = [str(int(M1[i:i+8], 16)) for i in range(0,len(M1), 8)]
    return " ".join(b0 + b1)

if __name__ == "__main__":
    signKey = PrivateKey.from_rand()

    leaf0 = 1337
    leaf1 = 7
    leaf2 = 1989
    leaf3 = 51966
    leaf4 = 1234
    leaf5 = 9999
    leaf6 = 0
    leaf7 = 6

    h0 = zok_hash(leaf0, leaf1)
    h1 = zok_hash(leaf2, leaf3)
    h2 = zok_hash(leaf4, leaf5)
    h3 = zok_hash(leaf6, leaf7)

    h00 = hashlib.sha256(h0 + h1).digest()
    h01 = hashlib.sha256(h2 + h3).digest()

    root = hashlib.sha256(h00 + h01).digest()


    directionSelector = "1 0 0"


    roout_out = zok_out_u32(root)

    msg1 = hashlib.sha256(int.to_bytes(leaf1, 64, "big")).digest()
    msg1 += msg1

    msg2 = hashlib.sha256(int.to_bytes(leaf2, 64, "big")).digest()
    msg2 += msg2

    msg3 = hashlib.sha256(int.to_bytes(leaf3, 64, "big")).digest()
    msg3 += msg3

    msg4 = hashlib.sha256(int.to_bytes(leaf4, 64, "big")).digest()
    msg4 += msg4

 
    leaf0 = [0, 0, 0, 0, 0, 0, 0, leaf0]
    leaf1 = [0, 0, 0, 0, 0, 0, 0, leaf1]
    leaf2 = [0, 0, 0, 0, 0, 0, 0, leaf2]
    leaf3 = [0, 0, 0, 0, 0, 0, 0, leaf3]
    leaf4 = [0, 0, 0, 0, 0, 0, 0, leaf4]


    path = [" ".join([str(i) for i in leaf0]), zok_out_u32(h1), zok_out_u32(h01)]



    #sys.stdout.write(" ".join([str(i) for i in leaf1]) + " " + zok_out_u32(root) + " " + directionSelector + " " + " ".join(path) + " ")

    # Signature
    sk = PrivateKey.from_rand()

    pk = PublicKey.from_private(sk)

    sig1 = sk.sign(msg1)
    sig2 = sk.sign(msg2)
    sig3 = sk.sign(msg3)
    sig4 = sk.sign(msg4)



            
    #Create Public Key
    verifyKey = PublicKey.from_private(signKey)

    outputs = [
        " ".join([str(i) for i in leaf1]) + " " + roout_out + " " + directionSelector + " " + " ".join(path) + " ",
        write_signature_for_zokrates_cli(pk, sig1, msg1),
        " ".join([str(i) for i in leaf1]) + " " + " " + directionSelector + " " + " ".join(path) + " ",
        write_signature_for_zokrates_cli(pk, sig2, msg2),
        " ".join([str(i) for i in leaf1]) + " "  + " " + directionSelector + " " + " ".join(path) + " ",
        write_signature_for_zokrates_cli(pk, sig3, msg3),
        " ".join([str(i) for i in leaf1]) + " "  + " " + directionSelector + " " + " ".join(path) + " ",
        write_signature_for_zokrates_cli(pk, sig4, msg4),
        
    ]

    sys.stdout.write(" ".join(outputs))
  

