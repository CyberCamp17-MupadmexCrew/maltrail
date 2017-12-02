import socket
import sys
from thread import *
import psutil
import platform
import re

from processes import get_pinfo_windows
from processes import init_detector
from processes import search_process

from processes import get_pinfo_windows

HOST = ''  # All interfaces
PORT = 2017
modes = {"get_pid": "get_pid", "kill_pid": "kill_pid"}

LINUX = 'Linux'
WINDOWS = 'Windows'
MAC = 'Darwin'


## Input Checks
def is_valid_ip(ip):
    m = re.match(r"^((\d{1,3})\.){3}(\d{1,3})$", ip)
    return bool(m) and all(map(lambda n: 0 <= int(n[:2]) <= 255, m.groups()))  # TODO fix it


def is_valid_port(port):
    return str(port).isdigit() and int(port) < 65535


def is_valid_prot(prot):
    return prot.lower() in ["tcp", "udp", "icmp"]


def is_valid_timestamp(tstamp):
    return bool(re.match(r"^\d{4}-\d{2}-\d{2} (\d{1,2}:){2}\d{1,2}\.\d{6}$", tstamp))


def is_valid_proc_name(pname):
    return bool(re.match(r"^[\w\d _-]+$", pname))


def check_get_pid_params(prot, ipdst, portdst, tstamp):
    return is_valid_prot(prot) and is_valid_ip(ipdst) and is_valid_port(port) and is_valid_timestamp(tstamp)


def check_kill_pid_params(pid, pname):
    return str(pid).isdigit() and is_valid_proc_name(pname)


####


# Example:
# Receive: get_pid,udp,192.168.0.200,8080,2017-07-03 23:29:32.689208
# Send: 1298,Firefox
def proc_get_pid(split_data):  # Return the response to the server
    prot, ipdst, portdst, tstamp = split_data
    prot = prot.lower()
    if not check_get_pid_params(prot, ipdst, portdst, tstamp):
        return "-1,error checking input"

    system = platform.system()

    if system == LINUX:
        reply = search_process(ipdst, portdst, tstamp)
    elif system == WINDOWS:
        reply = get_pinfo_windows(prot, portdst, ipdst)
    elif system == MAC:
        pass

    return reply


def init_sensors():
    system = platform.system()

    if system == LINUX:
        init_detector()


# Example: kill_pid,1987,Firefox
# Send: correct
def proc_kill_pid(split_data):  # Return the response to the server
    pid, pname = split_data
    pname = pname.lower()
    error = "error"
    if not check_kill_pid_params(pid, pname):
        return "error checking input"
    try:
        p = psutil.Process(int(pid))
        if pname == p.name():
            p.kill()
            return "correct"
        else:
            return error
    except:
        return error


## Process recived data
def proc_recv_data(con, data):
    split_data = data.rstrip().split(',')
    mode = split_data[0]
    if mode == modes["get_pid"]:
        reply = proc_get_pid(split_data[1:])

    elif mode == modes["kill_pid"]:
        reply = proc_kill_pid(split_data[1:])

    else:
        reply = "no correct mode"

    con.send(reply)


##### Socket Logic ####
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

init_detector()

try:
    s.bind((HOST, PORT))
except socket.error as msg:
    print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

s.listen(5)


def client_thread(con):
    while True:
        data = con.recv(1024)
        if not data:
            break
        proc_recv_data(con, data)
    con.close()


while True:
    con, addr = s.accept()
    start_new_thread(client_thread, (con,))

s.close()
