import asyncio


@asyncio.coroutine
def tcp_echo_client(message, loop):
    reader, writer = yield from asyncio.open_unix_connection("./echosocket")

    print('Send: %r' % message)
    writer.write(message.encode())

    data = yield from reader.read(100)
    print('Received: %r' % data.decode())

    print('Close the socket')
    writer.close()


message = 'Hello World!'
loop = asyncio.get_event_loop()
loop.run_until_complete(tcp_echo_client(message, loop))
loop.close()
