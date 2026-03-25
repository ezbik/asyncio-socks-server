import asyncio
import socket

import errno

from asyncio_socks_server.config import Config
from asyncio_socks_server.protocols import LocalTCP


class ProxyMan:
    def __init__(self, config: Config):
        self.config = config
        self.loop = asyncio.get_event_loop()
        self.accepting = True
        self.backoff = 0
        self.accept_failures = 0
        self.listening_socket = None

    async def start_server(self):

        self.listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listening_socket.setblocking(False)
        self.listening_socket.bind((self.config.LISTEN_HOST, self.config.LISTEN_PORT, ))
        self.listening_socket.listen(100)

        asyncio.create_task(self.safe_accept_loop())
        #print(f"Socket prepared {self.listening_socket}")


    async def safe_accept_loop(self):
        """Custom accept loop with backoff on EMFILE"""
        while True:
            if not self.accepting:
                await asyncio.sleep(0.1)
                continue

            try:
                # Accept a new connection (non-blocking)
                client_socket, addr = await self.loop.sock_accept(self.listening_socket)

                # Success! Reset failure counter
                self.accept_failures = 0
                self.backoff = 0

                # Make the client socket non-blocking
                client_socket.setblocking(False)

                # Create protocol instance
                protocol = LocalTCP(self.config)

                # Create transport for this connection
                transport =  await self.loop.create_connection(
                    lambda: protocol,  # Returns the NEW protocol instance
                    sock=client_socket,
                    #server_hostname=addr[0]
                )

                # Protocol gets connection_made called automatically

            except OSError as e:
                if e.errno == errno.EMFILE:  # Too many open files
                    self.accept_failures += 1

                    # Exponential backoff: 0.1, 0.2, 0.4, 0.8, 1.6, 3.2, 5.0 max
                    self.backoff = min(0.1 * (2 ** (self.accept_failures - 1)), 5.0)

                    print(f"EMFILE: Too many open files. "
                          f"Backing off for {self.backoff:.2f}s "
                          f"(failure #{self.accept_failures})")

                    # Pause accepting temporarily
                    self.accepting = False

                    # Schedule resume after backoff
                    self.loop.call_later(self.backoff, self.resume_accepting)

                elif e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    # No connections pending, normal condition - short sleep
                    await asyncio.sleep(0.01)
                else:
                    # Other socket errors
                    print(f"Accept error: {e}")
                    await asyncio.sleep(0.1)

    def resume_accepting(self):
        """Resume accepting connections after backoff"""
        self.accepting = True
        print("Resumed accepting connections")

    async def close_server(self):
        self.accepting = False
        if self.listening_socket:
            self.listening_socket.close()

