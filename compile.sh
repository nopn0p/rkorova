#!/bin/bash 
gcc -O0 -g0 -Werror -fPIC -c -o rk.o rk.c
gcc -O0 -g0 -Werror -shared -fPIC -s -Wl,-soname -Wl,1ibc.so -ldl -o 1ibc.so rk.o
rm rk.o
