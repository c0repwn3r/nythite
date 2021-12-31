import hashlib

DIGEST_HEX = 0
DIGEST_BINARY = 1


def hash_file(filename, digesttype=DIGEST_BINARY):
    with open(filename, 'rb') as f:
        hs = hashlib.sha512(f.read())
        if digesttype == DIGEST_BINARY:
            return hs.digest()
        else:
            return hs.hexdigest()
