# rkorova

bad userland LD_PRELOAD rootkit 

## Features 
* important strings are xor'ed out 
* hiding through magic GID / env var 
* totally awful

```
 ______     __  __     ______     ______     ______     __   __   ______    
/\  == \   /\ \/ /    /\  __ \   /\  == \   /\  __ \   /\ \ / /  /\  __ \   
\ \  __<   \ \  _"-.  \ \ \/\ \  \ \  __<   \ \ \/\ \  \ \ \'/   \ \  __ \  
 \ \_\ \_\  \ \_\ \_\  \ \_____\  \ \_\ \_\  \ \_____\  \ \__|    \ \_\ \_\ 
  \/_/ /_/   \/_/\/_/   \/_____/   \/_/ /_/   \/_____/   \/_/      \/_/\/_/ 
                                                                          
```
## Installation
* step 1: change default values 
* step 2: run compile.sh to compile 
* step 3: create magic user 
* step 4: replace ld_preload with librkorova.so
* step 5: set your magic env var in ~/.bash_profile or whatever 
* step 6: hide any other files not owned by you with chgrp (magic gid) (file) 

rkorova will (ideally) hide any files that are under the magic GID and/or the hidden user. in fact, you don't even need a user as long as you hide all files under the GID

## Known Issues 
rkorova is not actually meant to be deployed in a real engagement and is pretty awful at hiding in that regard. I am not responsible for any illegal / stupid things that happen because you decided to act el8 in front of your friends on IRC 
* If a file is hidden, it will appear in bash autocomplete but cannot be interacted with.
* rkorova sometimes completely breaks when git is involved 

## Default values: 
* MAGIC = "mochi"
* MAGICGID = 1337 
* EXECPW = installgentoo
* SHELLPW = bl1ng
* PROC = /proc
* DEFAULT_PORT = 61040
* IP = 127.0.0.1
* XOR key = 0x2A  


## References 

* https://haxelion.eu/article/LD_NOT_PRELOADED_FOR_REAL/
* Reverse Engineering for Beginners by Denis Yurichev
* http://fluxius.handgrep.se/2011/10/31/the-magic-of-ld_preload-for-userland-rootkits/
* https://blog.fpmurphy.com/2012/09/all-about-ld_preload.html
