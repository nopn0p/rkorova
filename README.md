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

## How to use 
1. Set values in `rkconst.h`
2. Compile 
3. Set up hidden directories 
4. Place `export` line into whatever shell startup file you want or in `/etc/profile`
5. Enjoy!
