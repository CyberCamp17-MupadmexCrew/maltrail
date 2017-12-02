import socket
import sys
from thread import *
import psutil
import platform

from processes import LinuxSensor, GenericSensor
from utils import sanitizer

HOST = ''  # All interfaces
PORT = 2017
modes = {"get_pid": "get_pid", "kill_pid": "kill_pid"}

LINUX = 'Linux'
WINDOWS = 'Windows'
MAC = 'Darwin'


def main():
    """
    Listens for a request, process it and replies with the corresponding PID or killing the specific PID
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sensor = get_specific_sensor()

    try:
        s.bind((HOST, PORT))
    except socket.error as msg:
        print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    s.listen(5)

    def client_thread(connection):
        while True:
            data = connection.recv(1024)
            if not data:
                break

            reply = process_received_data(data, sensor)
            connection.send(reply)

        connection.close()

    while True:
        connection, addr = s.accept()
        start_new_thread(client_thread, (connection,))

    s.close()


def get_specific_sensor():
    """
    :return: Platform specific sensor
    """
    system = platform.system()

    if system == LINUX:
        return LinuxSensor()
    elif system == WINDOWS:
        return GenericSensor()
    elif system == MAC:
        pass
    else:
        return GenericSensor()


def process_received_data(data, sensor):
    split_data = data.rstrip().split(',')
    mode = split_data[0]

    if mode == modes["get_pid"]:
        reply = _get_pid(split_data[1:], sensor)
    elif mode == modes["kill_pid"]:
        reply = _kill_pid(split_data[1:])
    else:
        reply = "-1, no correct mode"

    return reply


# Example:
# Receive: get_pid,udp,192.168.0.200,8080,2017-07-03 23:29:32.689208
# Send:
def _get_pid(split_data, sensor):
    """
    Uses the sensor to retrieve the PID and process name
    :param split_data: Data representing the request fields.
                       Example: get_pid,udp,192.168.0.200,8080,2017-07-03 23:29:32.689208
    :param sensor: Sensor to be used
    :return: PID and proccess name. Example: 1298,Firefox
    """
    prot, ip_dst, port_dst, timestamp = split_data
    prot = prot.lower()

    if not sanitizer.check_get_pid_params(prot, ip_dst, port_dst, timestamp):
        return "-1,error checking input"

    return sensor.search_process(prot, ip_dst, port_dst, timestamp)


def _kill_pid(split_data):
    """
    :param split_data: Data representing the request fields. Example: kill_pid,1987,Firefox
    :return error or successful
    """
    pid, pname = split_data
    pname = pname.lower()
    error = "error"

    if not sanitizer.check_kill_pid_params(pid, pname):
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


if __name__ == '__main__':
    main()