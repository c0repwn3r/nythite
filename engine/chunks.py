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

    def __len__(self):
        return len(self.list)


def parse_chunkdlist(dlist):
    # first split it into its chunks
    chunks = dlist.split(':')
    # first chunk is the id
    identifier = int(chunks[0])
    # second chunk is the filename
    filename = chunks[1]
    # third chunk is filesizes
    filesizes = chunks[2].split('/')
    original = int(filesizes[0])
    encrypted = original + int(filesizes[1])
    # fourth is sha512sum
    shasum = chunks[3]
    # assemble chunk
    chunk = Chunk(identifier, original, encrypted, filename, shasum)
    # return it
    return chunk


def parse_dlist(dlist):
    # split dlist into lines
    lines = dlist.split('\n')
    datalist = ChunkDataListing(1)
    for line in lines:
        datalist.append(parse_chunkdlist(line))
    return datalist


def print_chunkdata(chunkdata):
    for chunk in chunkdata.get_list():
        print(chunk)
