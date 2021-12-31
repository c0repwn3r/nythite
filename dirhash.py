from engine.hashing import hash_file, DIGEST_HEX

import os
import hashlib
import sys

dir1 = sys.argv[1]
dir2 = sys.argv[2]

dir1hashes = ''
dir2hashes = ''
dir1hash = ''
dir2hash = ''

for root, subdirs, files in os.walk(dir1):
    for filename in files:
        file_path = os.path.join(root, filename)
        filehash = hash_file(file_path, DIGEST_HEX)
        print('hashed', file_path, filehash)
        dir1hashes += filehash
for root, subdirs, files in os.walk(dir2):
    for filename in files:
        file_path = os.path.join(root, filename)
        filehash = hash_file(file_path, DIGEST_HEX)
        print('hashed', file_path, filehash)
        dir2hashes += filehash

dir1hash = hashlib.sha256(dir1hashes.encode()).hexdigest()
dir2hash = hashlib.sha256(dir2hashes.encode()).hexdigest()
print(dir1hash)
print(dir2hash)
if (dir1hash == dir2hash):
    print('Directories are exact matches (content-wise)')