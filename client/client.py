#!/usr/bin/python3
import ssl, socket

def main():
	context = ssl.create_default_context()
	context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
	context.verify_mode = ssl.CERT_NONE
	context.check_hostname = False
	conn = context.wrap_socket(socket.socket(socket.AF_INET),server_hostname='localhost')
	conn.connect(("localhost", 1234))
	conn.sendall(b"Hello World!")
	data = conn.read()
	print(data.decode('utf-8'))
	conn.shutdown(socket.SHUT_RDWR)
	conn.close()

if __name__ == "__main__":
	main()