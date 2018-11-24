import sys
sys.path.append('/mnt/c/Users/becga/Documents/crypto_pals')
# msg digest developed by Ron Rivest
# it informed the design for MD5 and SHA1 -- it is literally obsolete
# please please don't use this... remember this came before MD5 and NO ONE
# uses that who is serious about security
# THIS DIGEST IS 128 Bits

def Majority(x,y,z):
    return (x & y) | (y & z) | (x & z)

def Conditional(x,y,z):
    return (x & y) | (~x & z)

def Parity(x,y,z):
    return x ^ y ^ z

class MD4():
    def __init__():
        # low order bytes are first
        self.inner_state = [0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210]
        self.message = ""
    def Update():
        return
    def Sum():
        return

def main():
    return

if __name__ == "__main__":
    main()