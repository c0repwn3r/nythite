import argparse
import base64
import binascii

from engine.cipher import AESCipher
from engine.hashing import sha512_file
from engine.keys import generate_master_key, convert_key, load_salt, load_iv, load_key


KEY_TYPE_STRING = 0
KEY_TYPE_XKCL = 1

ACTION_DECRYPT_FILE = 2
ACTION_ENCRYPT_FILE = 3
ACTION_CONVERT_KEY = 4
ACTION_DUMP_KEY_INFO = 5
ACTION_GENERATE_KEY = 6


parser = argparse.ArgumentParser(
    description="Encrypt/decrypt files that are using the XKCL key system")
parser.add_argument('-k', '--key', type=str,
                    help='Specify a full word-based master key for encryption/decryption.')
parser.add_argument('-b', '--xkcl-key', type=str,
                    help='Specify a key in xkcl-b64 format to use for encryption/decryption')
parser.add_argument('-d', '--decrypt', type=str,
                    help='Specify a file to decrypt (cannot be used with --encrypt).')
parser.add_argument('-e', '--encrypt', type=str,
                    help='Specify a file to encrypt (cannot be used with --decrypt).')
parser.add_argument('-c', '--convert-key', type=str,
                    help='Convert a word-based key to an xkcl-b64 key. CANNOT be done the other way for technical reasons.')
parser.add_argument('-D', '--dump-key-info', type=str,
                    help='Specify a key in any format to dump information on it.')
parser.add_argument('-g', '--gen-key', type=str,
                    help='Generate a key of the type provided')
parser.add_argument('-o', '--output', type=str,
                    help='Set output file for encrypt/decrypt operations.')
args = parser.parse_args()


keytype = None
converto = None
action = None

key = None
mrkey = None

if (args.key is None and args.xkcl_key is None and args.encrypt is None and args.decrypt is None and args.convert_key is None and args.dump_key_info is None and args.gen_key is None):
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
    print('Converting key to xkcl-b64 format.', end='\r')
    key = args.convert_key
    converted = convert_key(key)
    print(converted)
    exit()


numbers = list('0123456789')
letters = list('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
base64c = list(
    '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/+=')

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
        print(
            f'key data (hex): {binascii.hexlify(base64.b64decode(key[2])).decode()}')
        print(f'key data (b64): {key[2]}')
        print('string conversion: none, cannot reverse hash')
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
        print(
            f'AES initialization vector (128-bit, decoded numeric): {load_iv(iv_text)}')
        key = load_key(load_salt(salt_text), key_text)
        print(f'key data (128-bit, string): {key_text}')
        print(f'key data (128-bit, binary): {base64.b64decode(key)}')
        print(
            f'key data (128-bit, hex): {binascii.hexlify(base64.b64decode(key)).decode()}')
        print(f'key data (128-bit, b64): {key}')
        print(f'xkcl-b64 conversion: {convert_key(mkey)}')
        print(f'installed wordlist version: {sha512_file("wordlist.txt")}')
        exit()


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

if (action == ACTION_GENERATE_KEY):
    keytype = args.gen_key.lower()
    if keytype in ['string', 'master', 'human-readable']:
        raw, result = generate_master_key()
        print(result)
    elif keytype in ['xkcl', 'xkcl-b64', 'machine-readable']:
        raw, result = generate_master_key()
        print(raw)
    else:
        raw, result = generate_master_key()
        print(raw)
        print(result)
