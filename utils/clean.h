#include <stdlib.h>
void clean(void *var, int len)
{ 
	memset(var, 0x00, len); 
	free(var); 
} 


