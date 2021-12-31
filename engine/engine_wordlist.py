import random

def load_wordlist():
    cl = []
    with open('wordlist.txt') as f:
        cl = f.read().split('\n')
    return cl

def generate_wordlist():
    initialwordlist = []
    wordlist = []

    with open('basewordlist.txt') as f:
        initialwordlist = f.read().split('\n')

    wordlist = random.sample(initialwordlist, 32767)
    if len(wordlist) != len(set(wordlist)):
        print('Duplicates')

    with open('wordlist.txt', 'w') as f:
        for i in wordlist:
            f.write(i + '\n')
