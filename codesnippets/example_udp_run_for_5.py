loop = asyncio.get_running_loop()

transport, protocol = await loop.create_datagram_endpoint(
    lambda: EchoServerProtocol(),
    local_addr=('127.0.0.1', 9999))

try:
    await asyncio.sleep(5)  # Serve for 5 seconds.
finally:
    transport.close()
