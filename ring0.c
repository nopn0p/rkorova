#include <linux/module.h> 
#include <linux/init.h> 
#include <linux/kernel.h> 

MODULE_LICENSE("GPL"); 
int rkinit(void); 
void rkexit(void); 
module_init(rkinit); 
module_exit(rkexit);

int rkinit(void)
{ 
	printk("m0000000\n"); 
	return 0; 
} 

void rkexit(void)
{ 
	printk("removed\n"); 
} 

