import re


def is_valid_ip(ip):
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
    return bool(m) and all(map(lambda n: 0 <= int(n[:2]) <= 255, m.groups()))


def is_valid_port(port):
    return str(port).isdigit() and int(port) < 65535


def is_valid_prot(prot):
    return prot.lower() in ["tcp", "udp", "icmp"]


def is_valid_timestamp(timestamp):
    return bool(re.match(r"^\d{4}-\d{2}-\d{2} (\d{1,2}:){2}\d{1,2}\.\d{6}$", timestamp))


def is_valid_proc_name(pname):
    return bool(re.match(r"^[\w\d _-]+$", pname))


def check_get_pid_params(prot, ip_dst, port_dst, timestamp):
    return is_valid_prot(prot) and is_valid_ip(ip_dst) and is_valid_port(port_dst) and is_valid_timestamp(timestamp)


def check_kill_pid_params(pid, pname):
    return str(pid).isdigit() and is_valid_proc_name(pname)
