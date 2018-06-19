#include <linux/module.h> 
#include <linux/init.h> 
#include <linux/kernel.h> 
#include <linux/slab.h> 
#include <linux/cred.h> 
#include <linux/version.h> 
#include <linux/cdev.h> 
#include <linux/fs.h> 
#include <linux/device.h> 
#define DEBUG 
MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("lolcow, github.com/blacchat"); 
MODULE_DESCRIPTION("ring0 portion of rkorova that handles persistence"); 
MODULE_VERSION("v1.0 alpha"); 

int rkinit(void); 
void rkexit(void); 
module_init(rkinit); 
module_exit(rkexit);

int rkinit(void)
{ 
	#ifdef DEBUG
	printk("m0000000\n"); 
	#endif 
	return 0; 
} 

void rkexit(void)
{ 
	#ifdef DEBUG 
	printk("removed\n"); 
	#endif
} 



