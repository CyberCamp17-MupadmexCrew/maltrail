import subprocess
import re
from datetime import datetime, timedelta

_NOT_FOUND = '-1,'
_PERIOD_OF_SEARCH = 10  # in seconds

_DATE_INPUT_FORMAT = '%Y-%m-%d %H:%M:%S.%f'  # Date format used by MalTrail
_DATE_FORMAT = '%m/%d/%Y %H:%M:%S'  # Date format used by audit


def init_detector():
    _exec_and_wait('/etc/init.d/audit.d start')
    _exec_and_wait('auditctl -a exit,always -F arch=b64 -S connect -k maltrail')


def close_detector():
    _exec_and_wait('auditctl -d exit,always -F arch=b64 -S connect -k maltrail')
    _exec_and_wait('/etc/init.d/audit.d stop')


def search_process(ip_dest, port_dest, timestamp):
    timestamp_end, timestamp_start = _parse_timestamp(timestamp)
    raw_last_connection = _get_last_connection(ip_dest, port_dest, timestamp_end, timestamp_start)

    if not raw_last_connection:
        return _NOT_FOUND

    return _parse_pid(raw_last_connection)


# Private functions

def _parse_timestamp(timestamp):
    end_datetime = datetime.strptime(timestamp, _DATE_INPUT_FORMAT)
    start_datetime = end_datetime - timedelta(seconds=_PERIOD_OF_SEARCH)

    return end_datetime.strftime(_DATE_FORMAT), start_datetime.strftime(_DATE_FORMAT)


def _get_last_connection(ip_dest, port_dest, timestamp_end, timestamp_start):
    if port_dest == 0:
        command = _get_command_without_port(ip_dest, timestamp_end, timestamp_start)
    else:
        command = _get_command(ip_dest, port_dest, timestamp_end, timestamp_start)

    return _exec_and_wait(command)


def _get_command(ip_dest, port_dest, timestamp_end, timestamp_start):
    return 'ausearch -i -sc connect -e 0 -k maltrail -te ' + timestamp_end + ' -ts ' + timestamp_start \
           + '| grep "laddr=' + ip_dest + ' lport=' + port_dest + '" -C 1 ' + '| tail -3'


def _get_command_without_port(ip_dest, timestamp_end, timestamp_start):
    return 'ausearch -i -sc connect -e 0 -k maltrail -te ' + timestamp_end + ' -ts ' + timestamp_start \
           + '| grep "laddr=' + ip_dest + '"  -C 1 ' + '| tail -3'


def _exec_and_wait(command):
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    proc.wait()
    return proc.stdout.read()


def _parse_pid(raw_connection):
    pid = re.search('pid=(\d+)', raw_connection).group(1)
    process_name = re.search('proctitle=(.+)', raw_connection).group(1)

    return pid + ',' + process_name
