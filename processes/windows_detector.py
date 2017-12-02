import psutil

def _find_pid(ipdst, portdst):
    for p in psutil.net_connections():
        if (p.raddr != () and p.raddr.ip == ipdst and p.raddr.port == int(portdst)):
            return p.pid
    return None

def get_pinfo_windows(prot, portdst, ipdst):
    unknown = "-1,unknown"
    if not prot.lower() in ["tcp","udp"]:
        return unknown
    pid = _find_pid(ipdst, portdst)
    if pid != None:
        p = psutil.Process(pid)
        pname = p.name()
        return str(pid)+","+pname
    return unknown