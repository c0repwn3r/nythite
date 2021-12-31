import tarfile
import os
import hashlib
from itertools import accumulate
from bisect import bisect
from random import randrange, shuffle, choice
import random
from unicodedata import name as unicode_name
import keyboard
import secrets
import base64
from pbkdf2 import PBKDF2
from emoji import *
import progressbar
import math
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad, unpad
from time import sleep, perf_counter

def sizeof_fmt(num, suffix="B"):
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"

# [>         ] 10% complete

DIGEST_HEX = 0
DIGEST_BINARY = 1

def hash_file(filename, digesttype=DIGEST_BINARY):
    with open(filename, 'rb') as f:
        hs = hashlib.sha512(f.read())
        if digesttype == DIGEST_BINARY:
            return hs.digest()
        else:
            return hs.hexdigest()

progressthing = [
    '[          ] 0% complete',
    '[          ] 1% complete',
    '[          ] 2% complete',
    '[          ] 3% complete',
    '[          ] 4% complete',
    '[          ] 5% complete',
    '[          ] 6% complete',
    '[          ] 7% complete',
    '[          ] 8% complete',
    '[          ] 9% complete',
    '[>         ] 10% complete',
    '[>         ] 11% complete',
    '[>         ] 12% complete',
    '[>         ] 13% complete',
    '[>         ] 14% complete',
    '[>         ] 15% complete',
    '[>         ] 16% complete',
    '[>         ] 17% complete',
    '[>         ] 18% complete',
    '[>         ] 19% complete',
    '[=>        ] 20% complete',
    '[=>        ] 21% complete',
    '[=>        ] 22% complete',
    '[=>        ] 23% complete',
    '[=>        ] 24% complete',
    '[=>        ] 25% complete',
    '[=>        ] 26% complete',
    '[=>        ] 27% complete',
    '[=>        ] 28% complete',
    '[=>        ] 29% complete',
    '[==>       ] 31% complete',
    '[==>       ] 32% complete',
    '[==>       ] 33% complete',
    '[==>       ] 34% complete',
    '[==>       ] 35% complete',
    '[==>       ] 36% complete',
    '[==>       ] 37% complete',
    '[==>       ] 38% complete',
    '[==>       ] 39% complete',
    '[===>      ] 40% complete',
    '[===>      ] 41% complete',
    '[===>      ] 42% complete',
    '[===>      ] 43% complete',
    '[===>      ] 44% complete',
    '[===>      ] 45% complete',
    '[===>      ] 46% complete',
    '[===>      ] 47% complete',
    '[===>      ] 48% complete',
    '[===>      ] 49% complete',
    '[====>     ] 50% complete',
    '[====>     ] 51% complete',
    '[====>     ] 52% complete',
    '[====>     ] 53% complete',
    '[====>     ] 54% complete',
    '[====>     ] 55% complete',
    '[====>     ] 56% complete',
    '[====>     ] 57% complete',
    '[====>     ] 58% complete',
    '[====>     ] 59% complete',
    '[=====>    ] 60% complete',
    '[=====>    ] 61% complete',
    '[=====>    ] 62% complete',
    '[=====>    ] 63% complete',
    '[=====>    ] 64% complete',
    '[=====>    ] 65% complete',
    '[=====>    ] 66% complete',
    '[=====>    ] 67% complete',
    '[=====>    ] 68% complete',
    '[=====>    ] 69% complete',
    '[======>   ] 70% complete',
    '[======>   ] 71% complete',
    '[======>   ] 72% complete',
    '[======>   ] 73% complete',
    '[======>   ] 74% complete',
    '[======>   ] 75% complete',
    '[======>   ] 76% complete',
    '[======>   ] 77% complete',
    '[======>   ] 78% complete',
    '[======>   ] 79% complete',
    '[=======>  ] 80% complete',
    '[=======>  ] 81% complete',
    '[=======>  ] 82% complete',
    '[=======>  ] 83% complete',
    '[=======>  ] 84% complete',
    '[=======>  ] 85% complete',
    '[=======>  ] 86% complete',
    '[=======>  ] 87% complete',
    '[=======>  ] 88% complete',
    '[=======>  ] 89% complete',
    '[========> ] 90% complete',
    '[========> ] 91% complete',
    '[========> ] 92% complete',
    '[========> ] 93% complete',
    '[========> ] 94% complete',
    '[========> ] 95% complete',
    '[========> ] 96% complete',
    '[========> ] 97% complete',
    '[========> ] 98% complete',
    '[========> ] 99% complete',
    '[=========>] 100% complete',
]

loop_iters = []

def hrtime(ms):
    if ms == False:
        return 'Calculating...'
    seconds=(ms/1000)%60
    seconds = int(seconds)
    minutes=(ms/(1000*60))%60
    minutes = int(minutes)
    hours = (ms/(1000*60*60))%24
    hours = int(hours)
    return f'{str(hours).zfill(2)}:{str(minutes).zfill(2)}:{str(seconds).zfill(2)}'

def print_progress(filename, filesize, filecount, totalcount, amtleft, eta, starttime):
    # [====>    ] 50% complete | compressing file test/test.txt (1/2 files, 110MiB left)
    progress = int(round((filecount / totalcount) * 100))
    string = f'{progressthing[progress]} | compressing file {filename} ({sizeof_fmt(filesize)}) | {filecount}/{totalcount}, {sizeof_fmt(amtleft)} left, time: {hrtime(eta)}/{hrtime((perf_counter()-starttime)*1000)}                                                '
    print(string, end='\r')

def compress_folder(ofname, source_dir):
    loop_iters = []
    print('Enumerating files...')
    filesize = 0
    filecount = 0
    tfcount = 0
    for root, subdirs, files in os.walk(source_dir):
        for filename in files:
            file_path = os.path.join(root, filename)
            filecount += 1
            filesize += os.path.getsize(file_path)
            print(f'{filecount} files ({sizeof_fmt(filesize)}), current file {file_path}                        ', end='\r')
    print(f'{filecount} files ({sizeof_fmt(filesize)}), current file {file_path}                        ')
    print('Compressing all files                                                                                                                                                   ')
    tfcount = filecount
    filecount = 0
    compstart = perf_counter()
    with tarfile.open(ofname, 'w:xz') as tar:
        for root, subdirs, files in os.walk(source_dir):
            for filename in files:
                start = perf_counter()
                file_path = os.path.join(root, filename)
                if len(loop_iters) != 0:
                    eta = (sum(loop_iters) / len(loop_iters)) * (tfcount - filecount)
                else:
                    eta = False
                print_progress(file_path, os.path.getsize(file_path), filecount, tfcount, filesize, eta * 1000, compstart)
                tar.add(file_path)
                end = perf_counter()
                loop_iters.append(end - start)
                filecount += 1
                filesize -= os.path.getsize(file_path)
    print('All files compressed                                                                                                                                   ')

def load_wordlist():
    cl = []
    with open('wordlist.txt') as f:
        cl = f.read().split('\n')
    return cl

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

def index_test():
    print('Running 32k indexing test')
    wordlist = load_wordlist()
    for i in progressbar.progressbar(range(32767)):
        word = wordlist[i]
        if wordlist.index(word) != i:
            print(wordlist.index(word))
            print('Index test failed on', i)
            return False
    return True

def genload_test():
    print('Running genload test')
    for i in progressbar.progressbar(range(500)):
        brkey, mkeytext = generate_master_key()
        brkey = brkey.split('.')
        salt = int(brkey[0])
        iv = int(brkey[1])
        key = brkey[2]
        mkeytext = mkeytext.split()
        salt_text = ' '.join(mkeytext[:2])
        iv_text = ' '.join(mkeytext[2:10])
        key_text = ' '.join(mkeytext[10:])
        salt_test = load_salt(salt_text)
        if salt_test != salt:
            print(f'{i} | testing salt FAILED!')
            print(salt_test, salt, salt_text)
            return False
        iv_test = load_iv(iv_text)
        if iv_test != iv:
            print(f'{i} | testing iv FAILED!')
            print(iv_test, iv_text, iv)
            return False
        key_test = load_key(salt, key_text)
        if key_test != key:
            print(f'{i} | testing key FAILED!')
            print(key_test, key_text, salt, key)
            return False
    return True

def run_tests():
    print('Running tests:')
    if not index_test():
        print('Index test failed!')
        return False
    if not genload_test():
        print('Genload test failed!')
        return False
    print('All tests passed')
    return True

def get_chunk_size(file):
    CHUNK_MINIMUM = 4096
    CHUNK_MAXIMUM = 512000000
    CHUNK_DIVISOR = 8

    filesize = os.path.getsize(file)
    chunksize = filesize / CHUNK_DIVISOR
    if chunksize < CHUNK_MINIMUM:
        chunksize = CHUNK_MINIMUM
    elif chunksize > CHUNK_MAXIMUM:
        chunksize = CHUNK_MAXIMUM
    
    return round(chunksize)

def calculate_keys_needed(file, chunksize):
    filesize = os.path.getsize(file)
    chunksneeded = int(math.ceil(filesize / chunksize))
    return chunksneeded

def read_in_chunks(file_object, chunk_size=1024):
    """Lazy function (generator) to read a file piece by piece.
    Default chunk size: 1k."""
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data

def generate_keyfile(count, encrypt=False):
    keys = []
    with open('keyfile', 'w') as f:
        for i in range(count):
            key = generate_master_key()[0]
            keys.append(key)
            f.write(key)
            if i != count-1:
                f.write('\n')
    return keys

def read_key(index):
    with open('keyfile') as f:
        data = f.read().split('\n')
        bk = data[index]
        bk = bk.split('.')
        return base64.b64decode(bk[2])

def read_master_key():
    with open('masterkey') as f:
        data = f.read()
        bk = data.split('.')
        return base64.b64decode(bk[2])

class AESCipher(object):
    def __init__(self, key):
        self.bs = AES.block_size
        self.key = key
    
    def encrypt(self, raw):
        raw = pad(raw, AES.block_size)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(raw)
    
    def decrypt(self, enc):
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[AES.block_size:]), AES.block_size)
    
    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * bytes(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

def readchunk(f, chunksize):
    return f.read(chunksize)

class Chunk:
    def __init__(self, index, originalsize, encryptedsize, filename, hashhex):
        self.index = index
        self.originalsize = originalsize
        self.encryptedsize = encryptedsize
        self.filename = filename
        self.hashhex = hashhex
    
    def __repr__(self):
        return f'chunk {self.index} {self.filename} size {self.originalsize}/{self.encryptedsize}, checksum {self.hashhex}'
    
    def get_chunkdlist(self):
        return f'{self.index}:{self.filename}:{self.originalsize}/{self.encryptedsize - self.originalsize}:{self.hashhex}'

class ChunkDataListing:
    def __init__(self, version):
        self.version = version
        self.list = []
    
    def append(self, chunk):
        self.list.append(chunk)
    
    def get_list(self):
        return self.list
    
    def get_dlist(self):
        string = ''
        for chunk in self.list:
            string += f'{chunk.get_chunkdlist()}\n'
        string = string[:-1]
        return string

chunkdata = ChunkDataListing(1)

def print_chunkdata():
    for chunk in chunkdata.get_list():
        print(chunk)

def encrypt_folder(folder, filename):
    print('Encrypting folder test/ for transfer')
    print('Compressing')
    compress_folder(f'{filename}.tar.xz', folder)
    print('Calculating chunk size')
    chunksize = get_chunk_size(f'{filename}.tar.xz')
    print(chunksize)
    print(f'Chunksize: {sizeof_fmt(chunksize)}')
    keycount = calculate_keys_needed(f'{filename}.tar.xz', chunksize)
    print(keycount, 'keys need to be generated')
    print('Generating keyfile')
    keys = generate_keyfile(keycount)
    print('Encrypting file')
    tarf = tarfile.open(f'{filename}.enc.tar', 'w:xz')
    with open(f'{filename}.tar.xz', 'rb') as f:
        i = 0
        for chunk in read_in_chunks(f, chunksize):
            # encrypt the data
            print('Encrypting chunk', i)
            print('- Collecting key from keyfile', end='\r')
            key = AESCipher(read_key(i))
            print('- Encrypting data            ', end='\r')
            encrypted = key.encrypt(chunk)
            print('- Validating data            ', end='\r')
            original = key.decrypt(encrypted)
            if original != chunk:
                print('! Failed!                          ')
                exit()
            print('- Writing chunk               ', end='\r')
            with open(f'{filename}-chunkid{i}encd.eadc', 'wb') as f:
                f.write(encrypted)
            tarf.add(f'{filename}-chunkid{i}encd.eadc')
            print('- Writing chunk data to header, please wait', end='\r')
            chunkid = Chunk(i, len(chunk), len(encrypted), f'{filename}-chunkid{i}encd.eadc', hash_file(f'{filename}-chunkid{i}encd.eadc', DIGEST_HEX))
            chunkdata.append(chunkid)
            os.unlink(f'{filename}-chunkid{i}encd.eadc')
            print(f'- Encrypted chunk successfully (chunksize {len(chunk)} encsize {len(encrypted)})')
            i += 1
    os.unlink(f'{filename}.tar.xz')
    print('Encrypting keyfile')
    key = None
    if os.path.exists('masterkey'):
        print('- Attempting to load master keyfile from file', end='\r')
        key = AESCipher(read_master_key())
    else:
        print('- Generating new master key                  ', end='\r')
        with open('masterkey', 'w') as f:
            keydata, keytext = generate_master_key()
            print('Key txt:', keytext)
            f.write(keydata)
        key = AESCipher(read_master_key())
    print('- Encrypting data', end='\r')
    with open('keyfile', 'rb') as f:
        bare = f.read()
        encrypted = key.encrypt(bare)
        print('- Verifying encryption                        ', end='\r')
        decrypted = key.decrypt(encrypted)
        if decrypted != bare:
            print('- Failed to encrypt! Data did not match.   ', end='\r')
            exit()
        print('- Keyfile encrypted successfully                 ')
    with open('keyfile.eakf', 'wb') as f:
        f.write(encrypted)
    tarf.add('keyfile.eakf')
    os.unlink('keyfile.eakf')
    print('Writing archive descriptor')
    archivedesc = chunkdata.get_dlist()
    with open('archdscrptr', 'w') as f:
        f.write(archivedesc)
    print('- Encrypting', end='\r')
    with open('archdscrptr', 'rb') as f:
        bare = f.read()
        encrypted = key.encrypt(bare)
        print('- Verifying   ', end='\r')
        decrypted = key.decrypt(encrypted)
        if decrypted != bare:
            print('- Failed to encrypt! Data did not match.', end='\r')
            exit()
        print('- Archive descriptor encrypted successfully                 ')
    with open('archdscrptr.eadf', 'wb') as f:
        f.write(encrypted)
    tarf.add('archdscrptr.eadf')
    os.unlink('archdscrptr.eadf')
    os.unlink('archdscrptr')
    os.unlink('keyfile')

encrypt_folder('test', 'test')