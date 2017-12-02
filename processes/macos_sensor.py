import subprocess
import os
import sys
import logging
import threading 
import logging.handlers

_NOT_FOUND = '-1,'
_LOG_PATH = "/tmp"                  # Absolute path for the log directory
_LOG_FILESIZE = 100000              # in Bytes
_LOG_COUNT = 1                      # number of logs to rotate
 

class MacOSSensor:
    def __init__(self):
        _init_logger()
        _init_thread()

    def search_process(self, prot, ip_dest, port_dest,timestamp):
        for filename in os.listdir(_LOG_PATH):
            if (filename.startswith('tcpdump.log')):
                proc = _process_file(_LOG_PATH+'/'+filename, prot, ip_dest, port_dest)
                if (proc):
                    return proc
        return _NOT_FOUND   
    
    def close(self):
        pass


 # Private functions

def _init_thread():
    print '[i] Initializing tcpdump'
    thread = threading.Thread(target=_print_tcpdump)        
    thread.start()    

def _init_logger():
    """
     Sets up basic configuration using the given parameters for the logger module 
     and defines log instances and handlers.
    """

logging.basicConfig(stream=sys.stdout,level=logging.DEBUG)      
logger = logging.getLogger('')  
handler=logging.handlers.RotatingFileHandler(_LOG_PATH+'/tcpdump.log','a',_LOG_FILESIZE,_LOG_COUNT)    
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)
    

def _get_timestamp(line):
    """
     Extracts the timestamp of a log line
    """
    return line[:15]
    
def _get_proc(line):
    """
     Extracts the process name and id for the given log line or _NOT_FOUND 
    """
    
    proc=line.partition('(')[-1].rpartition(')')[0]
    proc_name,_,proc_pid=proc.partition(' ')[-1].rpartition(':')
 
    if((proc == None) or (')' in proc)):
        return _NOT_FOUND
    else:
        if (proc_name == _NOT_FOUND):
            return _NOT_FOUND
        else:
            return proc_pid+','+proc_name
    
def _get_ips(line,mode=1): 
    """
     Extracts the ips for the given log line, the mode parameter is used to select the desired
     IP returned. 
    """

    ips=line.partition('IP ')[-1].rpartition(': ')[0]
    ip_src,_,p_src=ips.rpartition(' >')[0].rpartition('.')
    ip_dest,_,port_dest=ips.partition('> ')[-1].rpartition('.')

    if (mode == 1):
        return ip_dest,port_dest
    elif (mode == 2):
        ip_dest=ips.partition('> ')[-1]
        return ip_dest
    else:
        return ip_src,p_src,ip_dest,port_dest

def _print_tcpdump():
    """
     Writes the stdout of tcpdump to a file using the logger module 
    """
    c = subprocess.Popen((("tcpdump -nl -k NP").split()), stdout=subprocess.PIPE)
    for row in iter(c.stdout.readline, b''):
        logger.debug('%s',row.strip())

def _process_file(file, prot, ip_dest, port_dest):
    """
     Process a given file to extract the process matching the protocol and destination IP
    """

    fread = open(file,'r')
    for line in reversed(fread.readlines()):
        if(prot == 'icmp'):              
            if(("ICMP" in line) and (ip_dest == _get_ips(line,2))):
                return _get_proc(line)
        else:
            if ((ip_dest,port_dest) == _get_ips(line)):
                return _get_proc(line)
    