import sys 

def unxor(string, key="*"):
    return ''.join([chr(int(i, 16) ^ ord(key)) for i in string[1:].split("x")])

if __name__ == "__main__": 
    print(unxor(sys.argv[1], sys.argv[2]))
