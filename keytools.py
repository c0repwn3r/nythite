print('keytools')

import base64
from pbkdf2 import PBKDF2
import binascii

# hyperflexible sinuose craunch songwright cardamums unawful whop triclinium mitrer nonmutational gentianella culicines misascribe sheepcote dossers loather thurls duodenopancreatectomy

print('grab hexkey for openssl')
keydata = input('masterkey: ')

def load_wordlist():
    cl = []
    with open('wordlist.txt') as f:
        cl = f.read().split('\n')
    return cl

def load_salt(salt_text):
    wordlist = load_wordlist()

    salt_text = salt_text.split()

    # salt is 2 words (32 bit int)
    s0 = wordlist.index(salt_text[0])
    s1 = wordlist.index(salt_text[1])

    del wordlist

    # combine short to int
    return (s0 << 16) + s1

def load_iv(iv_text):
    wordlist = load_wordlist()

    iv_text = iv_text.split()

    # iv is 8 words (128 bit)
    s0 = wordlist.index(iv_text[0])
    s1 = wordlist.index(iv_text[1])
    s2 = wordlist.index(iv_text[2])
    s3 = wordlist.index(iv_text[3])
    s4 = wordlist.index(iv_text[4])
    s5 = wordlist.index(iv_text[5])
    s6 = wordlist.index(iv_text[6])
    s7 = wordlist.index(iv_text[7])

    i0 = (s0 << 16) + s1
    i1 = (s2 << 16) + s3
    i2 = (s4 << 16) + s5
    i3 = (s6 << 16) + s7

    l0 = (i0 << 32) + i1
    l1 = (i2 << 32) + i3

    iv = (l0 << 64) + l1

    return iv

def load_key(salt, key_passphrase):
    key = PBKDF2(key_passphrase, str(salt)).read(32)

    return key

print('loading salt')
mkeytext = keydata.split(' ')

salt_text = ' '.join(mkeytext[:2])
iv_text = ' '.join(mkeytext[2:10])
key_text = ' '.join(mkeytext[10:])

salt = load_salt(salt_text)
print('loading key')
key = load_key(salt, key_text)

print(binascii.hexlify(key))