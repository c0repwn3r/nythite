import tarfile
import os
import io

from utils.formatting import sizeof_fmt
from utils.progress import print_progress, on_progress, progresslist

from time import perf_counter


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
            print(
                f'{filecount} files ({sizeof_fmt(filesize)}), current file {file_path}                        ', end='\r')
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
                    eta = (sum(loop_iters) / len(loop_iters)) * \
                        (tfcount - filecount)
                else:
                    eta = False
                print_progress(file_path, os.path.getsize(
                    file_path), filecount, tfcount, filesize, eta * 1000, compstart)
                tar.add(file_path)
                end = perf_counter()
                loop_iters.append(end - start)
                filecount += 1
                filesize -= os.path.getsize(file_path)
    print('All files compressed                                                                                                                                   ')


def get_file_progress_file_object_class(on_progress):
    class FileProgressFileObject(tarfile.ExFileObject):
        def read(self, size, *args):
            on_progress(self.name, self.position, self.size)
            return tarfile.ExFileObject.read(self, size, *args)
    return FileProgressFileObject


class TestFileProgressFileObject(tarfile.ExFileObject):
    def read(self, size, *args):
        on_progress(self.name, self.position, self.size)
        return tarfile.ExFileObject.read(self, size, *args)


class ProgressFileObject(io.FileIO):
    def __init__(self, path, *args, **kwargs):
        self._total_size = os.path.getsize(path)
        io.FileIO.__init__(self, path, *args, **kwargs)

    def read(self, size):
        progress = int(round((self.tell() / self._total_size) * 100))
        if progress < 0:
            progress = 0
        if progress > 99:
            progress = 99
        string = f'decompressing | {progresslist[progress]}'
        print(string, end='\r')
        return io.FileIO.read(self, size)
