from engine.chunks import Chunk, ChunkDataListing
from engine.compression import compress_folder, get_file_progress_file_object_class, ProgressFileObject
from engine.chunks import get_chunk_size, calculate_keys_needed, parse_dlist
from engine.keys import generate_keyfile, read_key, generate_master_key, convert_key
from engine.files import read_in_chunks
from engine.cipher import AESCipher
from engine.hashing import hash_file, DIGEST_HEX

from utils.formatting import sizeof_fmt
from utils.progress import on_progress

import tarfile
import os
import base64
import shutil


def encrypt_folder(folder, filename):
    chunkdata = ChunkDataListing(1)
    print('Encrypting folder for transfer')
    print('Compressing')
    compress_folder(f'{filename}.tar.xz', folder)
    print('Calculating chunk size')
    chunksize = get_chunk_size(f'{filename}.tar.xz')
    print(chunksize)
    print(f'Chunksize: {sizeof_fmt(chunksize)}')
    keycount = calculate_keys_needed(f'{filename}.tar.xz', chunksize)
    print(keycount, 'keys need to be generated')
    print('Generating keyfile')
    generate_keyfile(keycount)
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
            chunkid = Chunk(i, len(chunk), len(
                encrypted), f'{filename}-chunkid{i}encd.eadc', hash_file(f'{filename}-chunkid{i}encd.eadc', DIGEST_HEX))
            chunkdata.append(chunkid)
            os.unlink(f'{filename}-chunkid{i}encd.eadc')
            print(
                f'- Encrypted chunk successfully (chunksize {len(chunk)} encsize {len(encrypted)})')
            i += 1
    os.unlink(f'{filename}.tar.xz')
    print('Encrypting keyfile')
    key = None
    print('- Generating new master key                  ', end='\r')
    keydata, keytext = generate_master_key()
    print('Key txt:', keytext)
    key = AESCipher(base64.b64decode(keydata.split('.')[2]))
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
    tarf.close()
    return keytext


def decrypt_folder(archive, output, key):
    print('Decrypting and decompressing folder')
    print('Decrypting archive metadata')
    print('- Creating output directory', end='\r')
    if os.path.exists(output) and os.path.isdir(output):
        shutil.rmtree(output)
        os.mkdir(output)
    else:
        os.mkdir(output)
    print('- Creating output directory                             ', end='\r')
    print('- Opening file handle      ', end='\r')
    main = tarfile.open(archive, 'r:xz')
    print('- Loading master key       ', end='\r')
    if '.' in key:
        print('- Key is probably in xkcl-b64 format, loading keydata', end='\r')
        keyid = key.split('.')[2]
        key = AESCipher(base64.b64decode(key.split('.')[2]))
    elif ' ' in key:
        print('- Key is probably in string format, converting key   ', end='\r')
        key = convert_key(key)
        print('- Key is now in xkcl-b64 format, loading keydata     ', end='\r')
        keyid = key.split('.')[2]
        key = AESCipher(base64.b64decode(key.split('.')[2]))
    else:
        print('- Unknown key type                                            ')
        exit()
    print(f'- Loaded key {keyid} without any errors             ')
    print('- Decompressing archive descriptor                               ', end='\r')
    main.extract('archdscrptr.eadf', output)
    print('- Reading encrypted archive descriptor   ', end='\r')
    encrypted = None
    with open(output + '/archdscrptr.eadf', 'rb') as f:
        encrypted = f.read()
    print('- Decrypting archive descriptor using master key', end='\r')
    decrypted, iv = key.decryptiv(encrypted)
    print('- Verifying decryption (re-encryption test)     ', end='\r')
    if key.encrypt(decrypted, iv) != encrypted:
        print('- Verification failed! Unable to decrypt archive descriptor, check that the key is correct (xkcltools is useful here)')
        exit()
    print('- Writing decrypted archive descriptor to file  ', end='\r')
    with open(output + '/archdscrptr', 'wb') as f:
        f.write(decrypted)
    print('- Deleting encrypted file                        ', end='\r')
    os.unlink(output + '/archdscrptr.eadf')
    print('- Parsing archive descriptor', end='\r')
    with open(output + '/archdscrptr') as f:
        archivedata = parse_dlist(f.read())
    print(f'- Loaded {len(archivedata)} chunk descriptors from file')
    print('- Decompressing keyfile', end='\r')
    main.extract('keyfile.eakf', output)
    print('- Reading encrypted keyfile', end='\r')
    encrypted = None
    with open(output + '/keyfile.eakf', 'rb') as f:
        encrypted = f.read()
    print('- Decrypting keyfile using master key', end='\r')
    decrypted, iv = key.decryptiv(encrypted)
    print('- Verifying decryption (re-encryption test)', end='\r')
    if key.encrypt(decrypted, iv) != encrypted:
        print('- Verification failed! Unable to decrypt keyfile, check that the key is correct (xkcltools is useful here)')
        exit()
    print('- Writing decrypted keyfile to file        ', end='\r')
    with open(output + '/keyfile', 'wb') as f:
        f.write(decrypted)
    print('- Deleting encrypted file                             ', end='\r')
    os.unlink(output + '/keyfile.eakf')
    print('- Loading keys from keyfile            ', end='\r')
    keys = []
    with open(output + '/keyfile') as f:
        keys = f.read().split('\n')
        keys = [key.split('.')[2] for key in keys]
    print(f'- Loaded {len(keys)} keys from keyfile     ')
    if len(keys) != len(archivedata):
        print(
            f'- Key mismatch! Archive descriptor expected {len(archivedata)} keys, but {len(keys)} were found in keyfile')
        exit()
    print('Decrypting chunks, this may take a while')
    chunks = archivedata.get_list()
    for chunk in chunks:
        print(f'>> Decrypting chunk {chunk.index}')
        print(' - Decompressing chunk', end='\r')
        main.extract(chunk.filename, output)
        print(' - Validating hash', end='\r')
        shasum = hash_file(output + '/' + chunk.filename, DIGEST_HEX)
        if (shasum != chunk.hashhex):
            print(
                f' - Failed! Hash of actual file {shasum} does not match expected hash of {chunk.hashhex}. The file may have been corrupted or tampered with.')
            exit()
        print(' - Reading file        ', end='\r')
        with open(output + '/' + chunk.filename, 'rb') as f:
            encrypted = f.read()
        print(' - Loading key ', end='\r')
        key = base64.b64decode(keys[chunk.index])
        key = AESCipher(key)
        print(f' - Loaded key {keys[chunk.index]}', end='\r')
        print(' - Decrypting file                                                                ', end='\r')
        decrypted, iv = key.decryptiv(encrypted)
        print(' - Verifying decryption (re-encryption test)', end='\r')
        if key.encrypt(decrypted, iv) != encrypted:
            print('- Verification failed! Unable to decrypt chunk, check that the key is correct (xkcltools is useful here)')
            exit()
        print(' - Writing decrypted data to file           ', end='\r')
        with open(output + '/' + chunk.filename, 'wb') as f:
            f.write(decrypted)
        print(' - Validating filesize                        ', end='\r')
        chunksize = os.path.getsize(output + '/' + chunk.filename)
        if chunksize != chunk.originalsize:
            print(
                f'- Failed! Chunk was decrypted with a size of {chunksize}, but it should be {chunk.originalsize}')
            exit()
        print(
            f' - Decrypted chunk {chunk.index} successfully                                                          ')
    print('Combining chunks to final archive')
    arc = open('temp.arc.tar.xz', 'wb')
    for chunk in chunks:
        print('- Combining chunk', chunk.index, end='\r')
        with open(output + '/' + chunk.filename, 'rb') as f:
            arc.write(f.read())
        print('- Combined chunk', chunk.index, '     ')
        os.unlink(output + '/' + chunk.filename)
    print('Decompressing archive, this might take a VERY long time')
    print('- Clearing directory')
    os.unlink(output + '/archdscrptr')
    os.unlink(output + '/keyfile')
    tarfile.TarFile.fileobject = get_file_progress_file_object_class(
        on_progress)
    arc = tarfile.open('r:xz', fileobj=ProgressFileObject('temp.arc.tar.xz'))
    arc.extractall(output)
    arc.close()
    os.unlink('temp.arc.tar.xz')
    print('decompressing | [=========>] 100% complete')
    print('Done')
