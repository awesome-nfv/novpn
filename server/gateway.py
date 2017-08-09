#!/usr/bin/python3
import asyncio, ssl

@asyncio.coroutine
def client_connected(reader, writer):
	data = yield from reader.read(12)
	print(data.decode('utf-8'))
	writer.write(b"hai there ^_^")
	writer.close()

sslcontext = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
sslcontext.verify_mode = ssl.CERT_NONE
sslcontext.load_cert_chain(certfile="cert.pem", keyfile="key.pem", password="12344321")
#sslcontext.load_verify_locations("root.pem")

print(sslcontext.cert_store_stats())
loop = asyncio.get_event_loop()
asyncio.async(asyncio.start_server(client_connected, host="127.0.0.1", port=1234, ssl=sslcontext))

loop.run_forever()