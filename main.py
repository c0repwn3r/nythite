import tarfile
import os
import base64
import progressbar
import math

from engine.aes import AESCipher
from engine.hashing import hash_file, DIGEST_BINARY, DIGEST_HEX
from engine.keys import *

from utils.progress import progresslist
from utils.formatting import hrtime, sizeof_fmt
from utils.wordlist import load_wordlist

from time import sleep, perf_counter

loop_iters = []

def print_progress(filename, filesize, filecount, totalcount, amtleft, eta, starttime):
    # [====>    ] 50% complete | compressing file test/test.txt (1/2 files, 110MiB left)
    progress = int(round((filecount / totalcount) * 100))
    string = f'{progresslist[progress]} | compressing file {filename} ({sizeof_fmt(filesize)}) | {filecount}/{totalcount}, {sizeof_fmt(amtleft)} left, time: {hrtime(eta)}/{hrtime((perf_counter()-starttime)*1000)}                                                '
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

def decrypt_folder(archive, output):
    pass

encrypt_folder('test', 'test')