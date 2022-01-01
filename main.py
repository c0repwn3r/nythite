from engine.operations import encrypt_folder, decrypt_folder
from utils.tests import index_test, genload_test

import sys

loop_iters = []


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


def print_help():
    print('Usage: nythite <encrypt|decrypt|send|recieve|help> <arguments>')
    print('---')
    print('   encrypt <folder> <archive> | Encrypt the specified folder and compress it into the specified archive.')
    print('   decrypt <archive> <folder> | Decrypt the specified archive into the specified folder.')
    print('   send <folder>              | Compress and encrypt the folder and send it to someone using a code.')
    print('   recieve <code>             | Recieve a folder from someone else, by putting in the code they gave you.')
    print('   help                       | Show this help screen.')
    print()


sys.argc = len(sys.argv)

if (sys.argc < 2 or sys.argc > 3):
    print('Too many or too little arguments!')
    print_help()
    exit()

actions = ['encrypt', 'decrypt', 'send', 'recieve', 'help']


if (sys.argv[1].lower() not in actions):
    print(f'Invalid action `{sys.argv[1]}`. See `help` for help.')
    exit()

action = sys.argv[1].lower()

if (action == 'help'):
    print_help()
    exit()

if (action == 'encrypt'):
    if (sys.argc != 3):
        print('Action `encrypt` requires an argument.')
        exit()
    folder = sys.argv[2]
    encrypt_folder(folder, folder)
    exit()
elif (action == 'decrypt'):
    if (sys.argc != 3):
        print('Action `decrypt` requires an argument.')
        exit()
    archive = sys.argv[2]
    key = input('Please input the archive master key: ')
    decrypt_folder(archive, 'decrypted', key)
# encrypt <folder>
# decrypt <archive>
# send <folder>
# recieve <code>
