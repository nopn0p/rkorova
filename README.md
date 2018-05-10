# rkorova

shitty LD_PRELOAD userland rootkit 

### Features
* (some) anti-debugging - strings are xor'ed out and rkorova cleans up after itself
* hides files and directories through username and magic GID  
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

rkorova will (ideally) hide any files that are under the magic GID and/or the hidden user. in fact, you don't even need a user as long as you hide all files under the GID

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

Change these values lol 

### Known issues 
* stat segfaults whenever it attempts to display gid - i'm working on a fix, go away 
* CLEAN macro is used inconsistently, which leads to MAGIC leaking - i know, will totally fix within the next 2 weeks 
* bash autocomplete shows hidden files - i have no idea why this is happening but i promise it won't
* file command states hidden files as "empty", not "nonexistent" - should be fixed as of May 8 2018, but probably won't work until i find the root cause of the problem

### Uses 
 
dont use this for anything  
its illegal 
