from wordlist import load_wordlist

def index_test():
    print('Running 32k indexing test')
    wordlist = load_wordlist()
    for i in progressbar.progressbar(range(32767)):
        word = wordlist[i]
        if wordlist.index(word) != i:
            print(wordlist.index(word))
            print('Index test failed on', i)
            return False
    return True

def genload_test():
    print('Running genload test')
    for i in progressbar.progressbar(range(500)):
        brkey, mkeytext = generate_master_key()
        brkey = brkey.split('.')
        salt = int(brkey[0])
        iv = int(brkey[1])
        key = brkey[2]
        mkeytext = mkeytext.split()
        salt_text = ' '.join(mkeytext[:2])
        iv_text = ' '.join(mkeytext[2:10])
        key_text = ' '.join(mkeytext[10:])
        salt_test = load_salt(salt_text)
        if salt_test != salt:
            print(f'{i} | testing salt FAILED!')
            print(salt_test, salt, salt_text)
            return False
        iv_test = load_iv(iv_text)
        if iv_test != iv:
            print(f'{i} | testing iv FAILED!')
            print(iv_test, iv_text, iv)
            return False
        key_test = load_key(salt, key_text)
        if key_test != key:
            print(f'{i} | testing key FAILED!')
            print(key_test, key_text, salt, key)
            return False
    return True