from utils.wordlist import load_wordlist
import secrets
from pbkdf2 import PBKDF2
import base64


def get_salt():
    # get 2 random 16-bit numbers
    s0 = secrets.randbelow(32767)
    s1 = secrets.randbelow(32767)
    # combine to int
    salt = (s0 << 16) + s1
    # get salt text
    wordlist = load_wordlist()
    salt_text = wordlist[s0] + ' ' + wordlist[s1]
    del wordlist
    return (salt, salt_text)


def load_salt(salt_text):
    wordlist = load_wordlist()

    salt_text = salt_text.split()

    # salt is 2 words (32 bit int)
    s0 = wordlist.index(salt_text[0])
    s1 = wordlist.index(salt_text[1])

    del wordlist

    # combine short to int
    return (s0 << 16) + s1


def get_iv():
    # get 8 random 16-bit numbers
    s0 = secrets.randbelow(32767)
    s1 = secrets.randbelow(32767)
    s2 = secrets.randbelow(32767)
    s3 = secrets.randbelow(32767)
    s4 = secrets.randbelow(32767)
    s5 = secrets.randbelow(32767)
    s6 = secrets.randbelow(32767)
    s7 = secrets.randbelow(32767)

    i0 = (s0 << 16) + s1
    i1 = (s2 << 16) + s3
    i2 = (s4 << 16) + s5
    i3 = (s6 << 16) + s7

    l0 = (i0 << 32) + i1
    l1 = (i2 << 32) + i3

    iv = (l0 << 64) + l1
    # get iv_text
    wordlist = load_wordlist()
    iv_text = wordlist[s0] + ' ' + wordlist[s1] + ' ' + wordlist[s2] + ' ' + wordlist[s3] + ' ' + wordlist[s4] + ' ' + wordlist[s5] + ' ' + wordlist[s6] + ' ' + wordlist[s7]

    return (iv, iv_text)


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


def get_key(salt):
    useless, key_passphrase = get_iv()
    key = PBKDF2(key_passphrase, str(salt)).read(32)

    return (key, key_passphrase)


def load_key(salt, key_passphrase):
    key = PBKDF2(key_passphrase, str(salt)).read(32)

    return base64.b64encode(key).decode()


def generate_master_key():
    salt, salt_text = get_salt()
    iv, iv_text = get_iv()
    key, key_text = get_key(salt)
    brkey = f'{salt}.{iv}.{base64.b64encode(key).decode()}'
    mkeytext = f'{salt_text} {iv_text} {key_text}'
    return (brkey, mkeytext)


def convert_key(key):
    # load the key manually then generate an xkcl-b64 key
    mkeytext = key.split(' ')
    salt_text = ' '.join(mkeytext[:2])
    iv_text = ' '.join(mkeytext[2:10])
    key_text = ' '.join(mkeytext[10:])
    salt = load_salt(salt_text)
    iv = load_iv(iv_text)
    key = load_key(salt, key_text)
    xkcl = f'{salt}.{iv}.{key}'
    return xkcl
