# Introduction
*muymacho* is an exploit for a DYLD_ROOT_PATH vulnerability present in Mac OS X 10.10.5 allowing local privilege escalation to root. It has been patched in El Capitan (10.11).

Luis Miras [@_luism](https://twitter.com/_luism)

It was a fun bug and exploit to develop. This [post](http://luismiras.github.io/muymacho-exploiting_DYLD_ROOT_PATH) is written as a guide through the process. 

> dyld_sim is a Mach-O file, but the exploit produces a dyld_sim that is just muymacho :)

# Usage

muymacho creates a malformed Mach-O library, dyld_sim, used to exploit
dyld through the DYLD_ROOT_PATH environment variable. For more info see:
http://luismiras.github.io


USAGE: muymacho.py [-d] base_directory

 -d : super sekret debug shellcode
 
 base_directory  : dyld_sim will be created in base_directory/usr/lib/dyld_sim

example:

    python muymacho.py /tmp

a malformed dyld_sim will be created in /tmp/usr/lib/dyld_sim
exploitation is then achived by executing:
  
    DYLD_ROOT_PATH=/tmp crontab

# super sekret debug shellcode 

Sometimes I am curious as to which segment was used in exploitation as well as the various ASLR addresses. In practice, the actual addresses are irrelevant. I included a debug shellcode that provides this information back to the user.

The super sekret debug shellcode is selected by passing a "-d" command line switch. After muymacho returns with the hashtag symbol (aka #), be sure to type in:

    echo "$MUYMACHO"

![debug infoz](http://luismiras.github.io/assets/debug_infoz.png)
