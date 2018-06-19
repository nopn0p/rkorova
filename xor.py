import crypt

def xor(string):
    return ''.join(list('\\x' + hex(ord(x) ^ 0x2A)[2:] for x in string))

def main(): 
    print("simple little xor util, included in rkorova for your convenience")
    word = input("word: ") 
    print(xor(word))
main()
