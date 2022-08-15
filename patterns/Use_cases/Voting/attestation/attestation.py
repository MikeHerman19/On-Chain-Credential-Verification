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

if __name__ == "__main__":
    signKey = PrivateKey.from_rand()

    min_zip_Code = "10000"
    max_zip_Code = "16000"

    attr1 = int.to_bytes(9, 64, "big") # Attr for Zipcode
    vc_zip = int.to_bytes(14052, 64, "big") #zipcode

    threshold = 990201510 #18.05.2001
    
    vc_dob = int.to_bytes(895507110, 64, "big") # birthdate | 18.05.1998
    attr2 = int.to_bytes(24, 64, "big") # Attr for dateofbirth


    resultHash1 = hashlib.sha256(b"".join([attr1[-32:], vc_zip[32:]])).digest()
    resultHash1 += resultHash1

    resultHash2 = hashlib.sha256(b"".join([attr2[-32:], vc_dob[-32:]])).digest()
    resultHash2 += resultHash2

    sig1 = signKey.sign(resultHash1)
    sig2 = signKey.sign(resultHash2)
            
    #Create Public Key
    verifyKey = PublicKey.from_private(signKey)

    outputs = [
        min_zip_Code, 
        max_zip_Code,
        " ".join([str(i) for i in struct.unpack(">16I", attr1)][-8:]),
        " ".join([str(i) for i in struct.unpack(">16I", vc_zip)][-8:]),
        write_signature_for_zokrates_cli(verifyKey, sig1, resultHash1),
        " ".join([str(i) for i in struct.unpack(">16I", attr2)][-8:]),
        " ".join([str(i) for i in struct.unpack(">16I", vc_dob)][-8:]),
        str(threshold),
        write_signature_for_zokrates_cli(verifyKey, sig2, resultHash2),
    ]
    sys.stdout.write(" ".join(outputs))

