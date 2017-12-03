from subprocess import Popen, PIPE
import psutil
import os, re

_DIR_PATH = "C:\Windows\Logs\maltrail\\"
_LOG_PATH = _DIR_PATH + "log.etl"
_NOT_FOUND = '-1,'
_SESSION_NAME = "Session1"
_STOP_LOGGING = "Stop-NetEventSession -Name '"+_SESSION_NAME+"'; Remove-NetEventSession -Name '"+_SESSION_NAME+"';"



class WindowsSensor:
    def __init__(self):
        print '[i] Initializing NetEventSession'
        max_size_logs = 5
        event_prov_name = "Microsoft-Windows-TCPIP"
        start_logging = "New-NetEventSession -Name '"+_SESSION_NAME+"' -CaptureMode SaveToFile -LocalFilePath '"+_LOG_PATH+"' -MaxFileSize "+str(max_size_logs)+"; Add-NetEventProvider -Name '"+event_prov_name+"' -SessionName '"+_SESSION_NAME+"'; Start-NetEventSession -Name '"+_SESSION_NAME+"';"
        _create_dir(_DIR_PATH)
        _create_file(_LOG_PATH)
        stdout,stderr = _execute_pwshell(_STOP_LOGGING)
        stdout,stderr = _execute_pwshell(start_logging)
        print '[i] Windows sensor ready'

    def search_process(self, prot, ip_dest, port_dest, timestamp):
        wait_log = "Stop-NetEventSession -Name '"+_SESSION_NAME+"';"
        stdout,stderr = _execute_pwshell(wait_log)
        
        get_event_str = "$logs = Get-WinEvent -Path '"+_LOG_PATH+"' -Oldest; foreach ($log in $logs){ $log.Message }" 
        stdout_events,stderr = _execute_pwshell(get_event_str)

        resume_log = "Start-NetEventSession -Name '"+_SESSION_NAME+"';"
        stdout,stderr = _execute_pwshell(resume_log)

        if (prot == "icmp"):
            search_pid = ip_dest
        else: 
            search_pid = ip_dest+":"+port_dest
        for msg in stdout_events.split('\n'):
            if (search_pid in msg):
                check = re.search('PID = (\d{1,5}).*', msg)
                if (check):
                    pid = check.group(1)
                    pname = psutil.Process(int(pid)).pname()
                    return str(pid) + ',' + pname
        
        return _NOT_FOUND

    def close(self):
        """
        Close the NetEvenSession before exit
        """
        stdout,stderr = _execute_pwshell(_STOP_LOGGING)



#Private functions

def _create_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)

def _create_file(path):
    """
    Check if the file exists and if it doesn't creates it
    """
    if not os.path.exists(path):
        f = open(path,'w')
        f.close()


def _pwshell_line(cmd):
    return 'powershell -command "'+cmd+'"'


def _execute_pwshell(cmd):
    """
    Executes the command of powershell received
    :param cmd: Command to execute
    :return: The standard out and error
    """
    pw_line = _pwshell_line(cmd)
    pw = Popen(pw_line, stdout=PIPE, stderr=PIPE, shell=True)
    stdout,stderr = pw.communicate()
    return (stdout,stderr)
