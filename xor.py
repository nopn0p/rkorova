import sys

# xor utility 
def xor(string, key="*"): 
    return ''.join(list('\\x' + hex(ord(x) ^ ord(key))[2:] for x in string))

if __name__ == "__main__":
    print(xor(sys.argv[1], sys.argv[2]))

