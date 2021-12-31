from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad, unpad


class AESCipher(object):
    def __init__(self, key):
        self.bs = AES.block_size
        self.key = key

    def encrypt(self, raw, iv=Random.new().read(AES.block_size)):
        raw = pad(raw, AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(raw)

    def decrypt(self, enc):
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[AES.block_size:]), AES.block_size)

    def decryptiv(self, enc):
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return (unpad(cipher.decrypt(enc[AES.block_size:]), AES.block_size), iv)

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * bytes(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]
