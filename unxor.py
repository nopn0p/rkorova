import sys 

def unxor(string):
    return ''.join([chr(int(i, 16) ^ 0x2A) for i in string[1:].split("x")])

def main(): 
    print(unxor(sys.argv[1]))

main()
