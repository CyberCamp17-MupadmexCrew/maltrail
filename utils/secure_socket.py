import socket
import ssl


class SecureSocket:
    CLIENT = 0
    SERVER = 1

    def __init__(self, mode, server_cert, client_cert, server_key=None, client_key=None):
        self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.client_cert = client_cert
        self.client_key = client_key
        self.server_cert = server_cert
        self.server_key = server_key
        self.ssl_socket = None

        if mode == self.CLIENT:
            self.context = self._get_ssl_client_context(False)
        elif mode == self.SERVER:
            self.context = self._get_ssl_server_context()

    def close(self):
        self.soc.close()

    # Server functions

    def bind(self, host, port):
        try:
            self.soc.bind((host, port))
        except socket.error as msg:
            print '[!] Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            raise socket.error

        self.soc.listen(5)

    def wait_connection(self):
        try:
            soc_open, addr = self.soc.accept()
            return self.context.wrap_socket(soc_open, server_side=True)
        except socket.error as msg:
            print '[!] Connection failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            raise socket.error

    # Client functions

    def connect(self, host, port):
        self.ssl_sock = self.context.wrap_socket(self.soc)
        self.ssl_sock.connect((host, port))

    def send(self, message):
        self.ssl_sock.write(message)

    def read(self):
        return self.ssl_sock.read()

    def _get_ssl_server_context(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(self.client_cert)
        context.load_cert_chain(certfile=self.server_cert, keyfile=self.server_key)

        return context

    def _get_ssl_client_context(self, check_hostname=True):
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = check_hostname
        context.load_verify_locations(self.server_cert)
        context.load_cert_chain(certfile=self.client_cert, keyfile=self.client_key)

        return context
