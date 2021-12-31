from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad, unpad
import argparse
import base64
from pbkdf2 import PBKDF2
import re
import binascii
import hashlib

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
        return s[:-ord(s[len(s)-1:])]

def load_wordlist():
    cl = []
    with open('wordlist.txt') as f:
        cl = f.read().split('\n')
    return cl

KEY_TYPE_STRING = 0
KEY_TYPE_XKCL = 1

ACTION_DECRYPT_FILE = 2
ACTION_ENCRYPT_FILE = 3
ACTION_CONVERT_KEY = 4
ACTION_DUMP_KEY_INFO = 5
ACTION_GENERATE_KEY = 6

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

    return base64.b64encode(key).decode()

def convert_key(key):
    wordlist = load_wordlist()
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

parser = argparse.ArgumentParser(description="Encrypt/decrypt files that are using the XKCL key system")
parser.add_argument('-k', '--key', type=str, help='Specify a full word-based master key for encryption/decryption.')
parser.add_argument('-b', '--xkcl-key', type=str, help='Specify a key in xkcl-b64 format to use for encryption/decryption')
parser.add_argument('-d', '--decrypt', type=str, help='Specify a file to decrypt (cannot be used with --encrypt).')
parser.add_argument('-e', '--encrypt', type=str, help='Specify a file to encrypt (cannot be used with --decrypt).')
parser.add_argument('-c', '--convert-key', type=str, help='Convert a word-based key to an xkcl-b64 key. CANNOT be done the other way for technical reasons.')
parser.add_argument('-D', '--dump-key-info', type=str, help='Specify a key in any format to dump information on it.')
parser.add_argument('-g', '--gen-key', type=str, help='Generate a key of the type provided')
parser.add_argument('-o', '--output', type=str, help='Set output file for encrypt/decrypt operations.')
args = parser.parse_args()



keytype = None
converto = None
action = None

key = None
mrkey = None

if (args.key == None and args.xkcl_key == None and args.encrypt == None and args.decrypt == None and args.convert_key == None and args.dump_key_info == None and args.gen_key == None):
    print('Refusing to do nothing, see -h/--help for information')
    exit()

requires_key = True
if (args.convert_key or args.dump_key_info or args.gen_key):
    requires_key = False

kc = 0
if (args.key):
    kc += 1
    keytype = KEY_TYPE_STRING
    key = args.key
if (args.xkcl_key):
    kc += 1
    keytype = KEY_TYPE_XKCL
    key = args.xkcl_key
if kc != 1 and requires_key:
    print('A key is required (there can\'t be more than one), see -h/--help for info')
    exit()

ac = 0
if (args.decrypt):
    ac += 1
    action = ACTION_DECRYPT_FILE
if (args.encrypt):
    ac += 1
    action = ACTION_ENCRYPT_FILE
if (args.convert_key):
    ac += 1
    action = ACTION_CONVERT_KEY
if (args.dump_key_info):
    ac += 1
    action = ACTION_DUMP_KEY_INFO
if (args.gen_key):
    ac += 1
    action = ACTION_GENERATE_KEY

if (ac != 1):
    print('An action is required (there can\'t be more than one), see -h/--help for info')
    exit()

if (args.convert_key):
    print(f'Converting key to xkcl-b64 format.', end='\r')
    key = args.convert_key
    converted = convert_key(key)
    print(converted)
    exit()

def sha512_file(filepath):
    with open(filepath, 'rb') as f:
        return hashlib.sha512(f.read()).hexdigest()

numbers = list('0123456789')
letters = list('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
base64c = list('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/+=')

if (args.dump_key_info):
    key = args.dump_key_info
    if '.' in key:
        # xkcl key type
        keytype = KEY_TYPE_XKCL
        print(f'key: {key}; type xkcl-b64')
    elif ' ' in key:
        # word key type
        keytype = KEY_TYPE_STRING
        print(f'key: {key}; type string')
    else:
        print('Unable to automatically determine key type, are you sure it\'s xkcl-compliant? Make sure the key is enclosed in quotes and has no extra characters.')
        exit()
    if keytype == KEY_TYPE_XKCL:
        key = key.split('.')
        print(f'pbkdf2 salt: {key[0]}')
        print(f'AES initialization vector: {key[1]}')
        print(f'key data (binary): {base64.b64decode(key[2])}')
        print(f'key data (hex): {binascii.hexlify(base64.b64decode(key[2])).decode()}')
        print(f'key data (b64): {key[2]}')
        print(f'string conversion: none, cannot reverse hash')
        print(f'installed wordlist version: {sha512_file("wordlist.txt")}')
        exit()
    else:
        mkey = key
        mkeytext = key.split(' ')
        salt_text = ' '.join(mkeytext[:2])
        iv_text = ' '.join(mkeytext[2:10])
        key_text = ' '.join(mkeytext[10:])

        print(f'pbkdf2 salt (32-bit, string): {salt_text}')
        print(f'pbkdf2 salt (32-bit, decoded numeric): {load_salt(salt_text)}')
        print(f'AES initialization vector (128-bit, string): {iv_text}')
        print(f'AES initialization vector (128-bit, decoded numeric): {load_iv(iv_text)}')
        key = load_key(load_salt(salt_text), key_text)
        print(f'key data (128-bit, string): {key_text}')
        print(f'key data (128-bit, binary): {base64.b64decode(key)}')
        print(f'key data (128-bit, hex): {binascii.hexlify(base64.b64decode(key)).decode()}')
        print(f'key data (128-bit, b64): {key}')
        print(f'xkcl-b64 conversion: {convert_key(mkey)}')
        print(f'installed wordlist version: {sha512_file("wordlist.txt")}')
        exit()

def read_master_key():
    with open('masterkey') as f:
        data = f.read()
        bk = data.split('.')
        return base64.b64decode(bk[2])

if (action == ACTION_DECRYPT_FILE):
    if keytype == KEY_TYPE_STRING:
        print('Converting key to machine-readable format')
        key = convert_key(key)
    key = AESCipher(base64.b64decode(key.split('.')[2]))
    filename = args.decrypt
    print(f'Decrypting {filename}')
    print('- Reading file', end='\r')
    encrypted = None
    with open(filename, 'rb') as f:
        encrypted = f.read()
    print('- Decrypting file', end='\r')
    decrypted, iv = key.decryptiv(encrypted)
    print('- Verifying decryption', end='\r')
    if key.encrypt(decrypted, iv) != encrypted:
        print('- Verification failed          ')
        print('Failed to decrypt file')
        exit()
    print('- Writing decrypted data to file', end='\r')
    if (args.output):
        with open(args.output, 'wb') as f:
            f.write(decrypted)
    else:
        with open(filename, 'wb') as f:
            f.write(decrypted)
    print('- Decrypted file successfully        ')
    exit()
    