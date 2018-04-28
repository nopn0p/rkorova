#!/bin/bash 
gcc -Wall -fno-builtin-ptrace -fno-builtin-open -fPIC -c -o rk.o rk.c
gcc -shared -fPIC -Wl,-soname -Wl,librkorova.so -ldl -o librkorova.so rk.o
rm rk.o
