import socket
import sys
from thread import *
import psutil
 
HOST = ''  # All interfaces
PORT = 2023
modes = {"get_pid":"get_pid", "kill_pid":"kill_pid"}

#Example:
#Receive: get_pid,udp,192.168.0.200,8080,2017-07-03 23:29:32.689208
#Send: 1298,Firefox
def proc_get_pid(con, split_data):
    prot, ipdst, portdst, tstamp = split_data
    #TODO reply
    return reply

#Example: kill_pid,1987,Firefox
#Send: correct
def proc_kill_pid(con, split_data):
    pid, pname = split_data
    error = "error"
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
        reply = proc_get_pid(con, split_data[1:])
    
    elif mode == modes["kill_pid"]:
        reply = proc_kill_pid(con, split_data[1:])
    
    else:
        reply = "no_correct_mode"
    
    con.sendall(reply)



##### Socket Logic ####
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 
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
        proc_recv_data(con,data)     
    con.close()
 
while True:
    con, addr = s.accept()     
    start_new_thread(client_thread ,(con,))
 
s.close()