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

    attr1 = int.to_bytes(9, 64, "big") # attr id for zip code
    vc_value1 = int.to_bytes(45054, 64, "big")

    resultHash1 = hashlib.sha256(b"".join([attr1[-32:], vc_value1[-32:]])).digest()
    resultHash1 += resultHash1

    attr2 = int.to_bytes(9, 64, "big") # attr id for zip code
    vc_value2 = int.to_bytes(45054, 64, "big")

    resultHash2 = hashlib.sha256(b"".join([attr2[-32:], vc_value2[-32:]])).digest()
    resultHash2 += resultHash2

    attr3 = int.to_bytes(9, 64, "big") # attr id for zip code
    vc_value3 = int.to_bytes(45054, 64, "big")

    resultHash3 = hashlib.sha256(b"".join([attr3[-32:], vc_value3[-32:]])).digest()
    resultHash3 += resultHash3

    attr4 = int.to_bytes(9, 64, "big") # attr id for zip code
    vc_value4 = int.to_bytes(45054, 64, "big")

    resultHash4 = hashlib.sha256(b"".join([attr4[-32:], vc_value4[-32:]])).digest()
    resultHash4 += resultHash4

    attr5 = int.to_bytes(9, 64, "big") # attr id for zip code
    vc_value5 = int.to_bytes(45054, 64, "big")

    resultHash5 = hashlib.sha256(b"".join([attr5[-32:], vc_value5[-32:]])).digest()
    resultHash5 += resultHash5

    attr6 = int.to_bytes(9, 64, "big") # attr id for zip code
    vc_value6 = int.to_bytes(45054, 64, "big")

    resultHash6 = hashlib.sha256(b"".join([attr6[-32:], vc_value6[-32:]])).digest()
    resultHash6 += resultHash6

    attr7 = int.to_bytes(9, 64, "big") # attr id for zip code
    vc_value7 = int.to_bytes(45054, 64, "big")

    resultHash7 = hashlib.sha256(b"".join([attr7[-32:], vc_value7[-32:]])).digest()
    resultHash7 += resultHash7

    attr8 = int.to_bytes(9, 64, "big") # attr id for zip code
    vc_value8 = int.to_bytes(45054, 64, "big")

    resultHash8 = hashlib.sha256(b"".join([attr8[-32:], vc_value8[-32:]])).digest()
    resultHash8 += resultHash8
    
    attr9 = int.to_bytes(9, 64, "big") # attr id for zip code
    vc_value9 = int.to_bytes(45054, 64, "big")

    resultHash9 = hashlib.sha256(b"".join([attr9[-32:], vc_value9[-32:]])).digest()
    resultHash9 += resultHash9

    attr10 = int.to_bytes(9, 64, "big") # attr id for zip code
    vc_value10 = int.to_bytes(45054, 64, "big")

    resultHash10 = hashlib.sha256(b"".join([attr10[-32:], vc_value10[-32:]])).digest()
    resultHash10 += resultHash10


    sig1 = signKey.sign(resultHash1)
    sig2 = signKey.sign(resultHash2)
    sig3 = signKey.sign(resultHash3)
    sig4 = signKey.sign(resultHash4)    
    sig5 = signKey.sign(resultHash5)    
    sig6 = signKey.sign(resultHash6)
    sig7 = signKey.sign(resultHash7)
    sig8 = signKey.sign(resultHash8)
    sig9 = signKey.sign(resultHash9)
    sig10 = signKey.sign(resultHash10)

            
    #Create Public Key
    verifyKey = PublicKey.from_private(signKey)

    outputs = [
        "1337",
        "51966",
        " ".join([str(i) for i in struct.unpack(">16I", attr1)][-8:]),
        " ".join([str(i) for i in struct.unpack(">16I", vc_value1)][-8:]),
        write_signature_for_zokrates_cli(verifyKey, sig1, resultHash1),
        " ".join([str(i) for i in struct.unpack(">16I", attr2)][-8:]),
        " ".join([str(i) for i in struct.unpack(">16I", vc_value2)][-8:]),
        write_signature_for_zokrates_cli(verifyKey, sig2, resultHash2),
        " ".join([str(i) for i in struct.unpack(">16I", attr3)][-8:]),
        " ".join([str(i) for i in struct.unpack(">16I", vc_value3)][-8:]),
        write_signature_for_zokrates_cli(verifyKey, sig3, resultHash3),        
        " ".join([str(i) for i in struct.unpack(">16I", attr4)][-8:]),
        " ".join([str(i) for i in struct.unpack(">16I", vc_value4)][-8:]),
        write_signature_for_zokrates_cli(verifyKey, sig4, resultHash4),
        " ".join([str(i) for i in struct.unpack(">16I", attr5)][-8:]),
        " ".join([str(i) for i in struct.unpack(">16I", vc_value5)][-8:]),
        write_signature_for_zokrates_cli(verifyKey, sig5, resultHash5),
        " ".join([str(i) for i in struct.unpack(">16I", attr6)][-8:]),
        " ".join([str(i) for i in struct.unpack(">16I", vc_value6)][-8:]),
        write_signature_for_zokrates_cli(verifyKey, sig6, resultHash6),
        " ".join([str(i) for i in struct.unpack(">16I", attr7)][-8:]),
        " ".join([str(i) for i in struct.unpack(">16I", vc_value7)][-8:]),
        write_signature_for_zokrates_cli(verifyKey, sig7, resultHash7),
        " ".join([str(i) for i in struct.unpack(">16I", attr8)][-8:]),
        " ".join([str(i) for i in struct.unpack(">16I", vc_value8)][-8:]),
        write_signature_for_zokrates_cli(verifyKey, sig8, resultHash8),
        " ".join([str(i) for i in struct.unpack(">16I", attr9)][-8:]),
        " ".join([str(i) for i in struct.unpack(">16I", vc_value9)][-8:]),
        write_signature_for_zokrates_cli(verifyKey, sig9, resultHash9),
        " ".join([str(i) for i in struct.unpack(">16I", attr10)][-8:]),
        " ".join([str(i) for i in struct.unpack(">16I", vc_value10)][-8:]),
        write_signature_for_zokrates_cli(verifyKey, sig10, resultHash10),
    ]
    
    sys.stdout.write(" ".join(outputs))

