# rkorova: LD_PRELOAD rootkit
This is an `LD_PRELOAD` rootkit I wrote several years ago in high school and have been trying sporadically to improve ever since. 

## Features 
- Important strings are xor'ed out 
- ptrace disabling  
- Memory cleaning 
- Process hiding (currently only through magic strings) 
- File hiding through magic strings or GID 
- Not detected by rkhunter (as of 2020) 

## Planned features 
- Port hiding 
- Reverse shell 
- Self-destruct feature
- VM detection 
- Better anti-debugging features
- Better code 
- C2 client 
- Syscall hooking with ptrace

## Known issues 
The `LD_PRELOAD` trick does not work in these cases: 
1. statically linked binaries 
2. any program that uses the `asm` compiler to make direct syscalls 
3. Golang programs, because they use their own syscall wrappers
4. Constructors are not multithread-safe :(

## Disclaimer 
I am not responsible for anything stupid, illegal or otherwise unethical you do with this. This is something I wrote for fun/educational purposes and is not meant to be used for anything else. 
