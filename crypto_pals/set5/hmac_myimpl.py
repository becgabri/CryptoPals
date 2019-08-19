# HMAC SHA 256
import sha256
OPAD = int("0x" + ("5c" * (512 // 8)), 16)
IPAD = int("0x" + ("36" * (512 // 8)), 16)
BLOCK_SIZE = 512

def SHA256_HMAC(key, msg):
    # H(k \oplus opad || H(k \oplus ipad || msg)) 
    init_hash = sha256.SHA256()
    init_hash.Update(key)
    hashed_key = init_hash.Sum()
    hashed_key = hashed_key << 256
    assert(hashed_key < ((1 << BLOCK_SIZE) - 1))
    outer_key = hashed_key ^ OPAD
    inner_key = hashed_key ^ IPAD

    innerHashDigest = sha256.SHA256()
    innerHashDigest.Update(inner_key.to_bytes(512 >> 3,byteorder='big') + msg)
    innerHashMsg = (innerHashDigest.Sum()).to_bytes(256 >> 3,byteorder='big')

    outerHashDigest = sha256.SHA256()
    outerHashDigest.Update(outer_key.to_bytes(512 >> 3,byteorder='big') + innerHashMsg)
    outerHashMsg = (outerHashDigest.Sum()).to_bytes(256 >> 3,byteorder='big')

    return outerHashMsg
