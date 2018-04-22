# rkorova

terrible LD_PRELOAD userland rootkit 

### Features
* (some) anti-debugging - strings are xor'ed out and rkorova cleans up after itself
* hides files and directories through username and magic GID comparisons 
* shitty plaintext backconnect shell 

Yes, I am aware that the implementation of stat in some hooked functions is inconsistent. 

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

### Disclaimer 
I am not responsible for any illegal use of this software. Please don't use this rootkit. 
