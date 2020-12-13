#!/bin/bash 
gcc -shared -fPIC -masm=intel rk.c -o 1ibc.so -ldl 
