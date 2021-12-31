import os
import math


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
