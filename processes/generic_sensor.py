import psutil


class GenericSensor:
    def __init__(self):
        pass

    def search_process(self, prot, ip_dst, port_dst, timestamp):
        unknown = "-1,"
        if not prot.lower() in ["tcp", "udp"]:
            return unknown

        pid = _find_pid(ip_dst, port_dst)

        if pid is None:
            return unknown

        p = psutil.Process(pid)
        pname = p.name()
        return str(pid) + "," + pname

    def close(self):
        pass

def _find_pid(ip_dst, port_dst):
    for p in psutil.net_connections():
        if p.raddr != () and p.raddr.ip == ip_dst and p.raddr.port == int(port_dst):
            return p.pid
    return None
