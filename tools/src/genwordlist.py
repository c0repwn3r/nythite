import random
import sys

initialwordlist = []
wordlist = []

with open('meta/basewordlist.txt') as f:
    initialwordlist = f.read().split('\n')

wordlist = random.sample(initialwordlist, 32767)
if len(wordlist) != len(set(wordlist)):
    print('Duplicates')

with open(f'../wordlists/{sys.argv[1]}.txt', 'w') as f:
    for i in wordlist:
        f.write(i + '\n')
