#include "../rkconst.h" 
#include <stdio.h>

#define SEPPUKU() *(int *)0=0

#define CHECK_CPUID(x, result) \
{ \
	__asm__ ( \
		"xor eax, eax;" \
		"inc eax;" \
		"cpuid;" \
		"bt ecx, 0x1f;" \
		"jc inVM;" \
		"mov %0, 0x0;" \
		"jmp notinVM;" \
		"inVM:; " \
		"mov %0, 0x1;" \
		"notinVM:; " \
		"nop;"  \
		: "=r" ( x )\
		: \
		: "eax", "ebx", "ecx", "edx"); \
	(*(result)) = x; \
} 

#define CHECK_VENDORID(vendorid) \
{ \
	int id[3]; \
	__asm__("xor eax, eax;"); \
 	__asm__("cpuid;"); \
	__asm__("mov %0, ebx": "=r" (id[0])); \
	__asm__("mov %0, edx": "=r" (id[1])); \
	__asm__("mov %0, ecx": "=r" (id[2])); \
	strcpy(vendorid, id); \
}


