def load_wordlist():
    cl = []
    with open('wordlists/current.txt') as f:
        cl = f.read().split('\n')
    return cl
