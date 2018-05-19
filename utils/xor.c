void xor(char *s)
{
       int i, key = 0x2A;
       for(i=0; i<strlen(s); i++) s[i] ^= key;
}

