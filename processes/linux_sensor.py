import subprocess
import re
import datetime

_NOT_FOUND = '-1,'
_WINDOW_OF_SEARCH = 10  # in seconds

_DATE_INPUT_FORMAT = '%Y-%m-%d %H:%M:%S.%f'  # Date format used by MalTrail
_DATE_FORMAT = '%m/%d/%Y %H:%M:%S'  # Date format used by audit


class LinuxSensor:
    def __init__(self):
        print '[i] Initializing audit daemon and hooking up rules'
        _exec_and_wait('/etc/init.d/auditd start')
        _exec_and_wait('auditctl -a exit,always -F arch=b64 -S connect -k maltrail')
        print '[i] Linux sensor ready'

    def search_process(self, prot, ip_dest, port_dest, timestamp):
        timestamp_end, timestamp_start = _parse_timestamp(timestamp)
        raw_last_connection = _get_last_connection(ip_dest, port_dest, timestamp_end, timestamp_start)

        if not raw_last_connection:
            return _NOT_FOUND

        return _parse_pid(raw_last_connection)

    def close(self):
        _exec_and_wait('auditctl -d exit,always -F arch=b64 -S connect -k maltrail')
        _exec_and_wait('/etc/init.d/auditd stop')


# Private functions

def _parse_timestamp(timestamp):
    """
     Parses the timestamp formatted by MalTrail and return two datetimes representing the given timestamp and
     another one shifted by _WINDOW_OF_SEARCH seconds
    """
    end_datetime = datetime.datetime.strptime(timestamp, _DATE_INPUT_FORMAT)
    start_datetime = end_datetime - datetime.timedelta(seconds=_WINDOW_OF_SEARCH)

    return end_datetime.strftime(_DATE_FORMAT), start_datetime.strftime(_DATE_FORMAT)


def _get_last_connection(ip_dest, port_dest, timestamp_end, timestamp_start):
    """
     Get the last audit log entry for the given ip, port and time window
    :param ip_dest:
    :param port_dest:
    :param timestamp_end: End time for the search
    :param timestamp_start: Start time for the search
    :return: Last audit log entry in string format
    """

    if port_dest == '0':
        command = _get_command_without_port(ip_dest, timestamp_end, timestamp_start)
    else:
        command = _get_command(ip_dest, port_dest, timestamp_end, timestamp_start)

    print '[i] Command: ' + command

    return _exec_and_wait(command)


def _get_command(ip_dest, port_dest, timestamp_end, timestamp_start):
    """
    Get the ausearch command to perform the search
    """
    return 'ausearch -i -sc connect -k maltrail -te ' + timestamp_end + ' -ts ' + timestamp_start \
           + ' | grep "' + ip_dest + ' .*' + port_dest + '" -C 1 ' + '| tail -3'


def _get_command_without_port(ip_dest, timestamp_end, timestamp_start):
    """
    Get the ausearch command to perform the search without taking into account the port
    """
    return 'ausearch -i -sc connect -k maltrail -te ' + timestamp_end + ' -ts ' + timestamp_start \
           + ' | grep "' + ip_dest + '"  -C 1 ' + '| tail -3'


def _exec_and_wait(command):
    """
      Exec the given command, wait until its completion and return the result
    """
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    proc.wait()
    return proc.stdout.read()


def _parse_pid(raw_connection):
    print '[i] Raw response: ' + raw_connection
    pid = re.search(' pid=(\d+)', raw_connection).group(1)
    process_name = re.search('proctitle=(.+)', raw_connection).group(1)

    return pid + ',' + process_name
