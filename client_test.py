from utils import SecureSocket

SENSOR_CERT_FILE = 'misc/cert_sensor.pem'
SENSOR_KEY_FILE = 'misc/key_sensor.pem'
SERVER_CERT_FILE = 'misc/server.pem'

socket = SecureSocket(SecureSocket.CLIENT, client_cert=SERVER_CERT_FILE, server_cert=SENSOR_CERT_FILE,
                      server_key=SENSOR_KEY_FILE)

socket.connect('localhost', 2017)
socket.send("holi")
print socket.read()
