from engine.operations import encrypt_folder, decrypt_folder
from engine.tests import index_test, genload_test

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


encrypt_folder('test', 'test')
key = input('Please paste your master key here')
decrypt_folder('test.enc.tar', 'test-decrypted', key)
