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
- libpcap hooks
- Reverse shell 
- Self-destruct feature
- VM detection (implemented a little bit)
- Better anti-debugging features
- Better code (never happening lol)
- C2 client 
- Syscall hooking with ptrace

## Requirements 
- gcc 
- libc6 (duh) 
- nscd (this will totally break everything if it is not installed) 
