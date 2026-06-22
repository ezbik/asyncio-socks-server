import asyncio
import itertools
import socket
from asyncio.streams import StreamReader
from socket import AF_INET, AF_INET6, inet_ntop, inet_pton
from typing import Optional, Tuple
import random

from asyncio_socks_server.authenticators import AUTHENTICATORS_CLS_LIST, NoAuthenticator
from asyncio_socks_server.config import Config
from asyncio_socks_server.exceptions import (
    AuthenticationError,
    CommandExecError,
    HeaderParseError,
    NoAtypAllowed,
    NoAuthMethodAllowed,
    NoCommandAllowed,
    NoVersionAllowed,
    SocksException,
)
from asyncio_socks_server.logger import access_logger, error_logger, logger
from asyncio_socks_server.utils import get_socks_atyp_from_host
from asyncio_socks_server.values import SocksAtyp, SocksCommand, SocksRep
import re
import time
import ipaddress

UDP_HOLE_PUNCH_DST_PORT=999

def find_free_udp_port(start, end):
    ports = list(range(start, end))
    random.shuffle(ports)
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            try:
                s.bind(('0.0.0.0', port))
                return port
            except OSError:
                continue
    raise RuntimeError("No free port found in range.")

class SpeedAnalyzer:
    def __init__(self):
        self.data = []  # Data structure to store (timestamp, amount_of_bytes) tuples

    def add_data(self, timestamp, amount_of_bytes):
        self.data.append((timestamp, amount_of_bytes))

    def calculate_average_speed(self):
        duration=3
        current_time = time.time()
        start_time = current_time - duration

        total_bytes = 0
        count = 0

        if len(self.data)>1000:
            self.cleanup_data()

        for timestamp, bytes_ in self.data[::-1]:
            if timestamp < start_time :
                break

            total_bytes += bytes_
            count += 1
        if count == 0:
            return 0
        else:
            return round(total_bytes / ( duration * 1000 * 1.1 ) ) 
            #Average Kbytes/s

    def cleanup_data(self):
            current_time = time.time()
            ten_seconds_ago = current_time - 10
            self.data = [(ts, bytes_) for ts, bytes_ in self.data if ts >= ten_seconds_ago]

DL=SpeedAnalyzer()
UL=SpeedAnalyzer()


def query(resolver, config, name) :
    try:
        ip_mode=config.IP_MODE
        if ip_mode == 4:
            query_types= ['A']
        elif ip_mode == 6:
            query_types= ['AAAA']
        elif ip_mode == 46:
            query_types= ['A' , 'AAAA']
        elif ip_mode == 64:
            query_types= [ 'AAAA', 'A' ]
        else:
            raise ValueError(f"Invalid IP_MODE: {ip_mode}")

        answers = []

        for query_type in query_types:
            try:
                answers = resolver.resolve(name, query_type)
                for rdata in answers:
                    return rdata.to_text()
            except Exception as e : # (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
                print(f'!!EXCEPTION!! while resolving {name} {query_type}: {e}')
                continue  # Try next query type
      
    except Exception as e:
        print("DNS query error:", e)

def acl(config, DST_ADDR):
    try:
        dst_ip = ipaddress.ip_address(DST_ADDR)
    except ValueError:
        dst_ip = None  # It's a domain, not an IP
    for banned in config.BANNED_DST:
        # Check if it's an IP network or address
        try:
            net = ipaddress.ip_network(banned, strict=False)
            if dst_ip and dst_ip in net:
                return -1
        except ValueError:
            # Not an IP, assume it's a domain pattern
            if re.search(rf'^(|.+\.){banned}$', DST_ADDR, re.IGNORECASE) :
                return -1
    return 0  # Allowed


class HolePunchProtocol(asyncio.DatagramProtocol):
    def __init__(self, peername):
        self.peername = peername

    def connection_made(self, transport):
        transport.sendto(b"HOLEPUNCH", self.peername)
        transport.close()  #  close immediately after send

class LocalTCP(asyncio.Protocol):
    STAGE_NEGOTIATE = 0
    STAGE_CONNECT = 1
    STAGE_UDP_ASSOCIATE = 3
    STAGE_DESTROY = -1

    def __init__(self, config: Config):
        self.config = config
        self.stage = None
        self.transport = None
        self.remote_tcp = None
        self.local_udp = None
        self.peername = None
        self.stream_reader = StreamReader()
        self.negotiate_task = None
        self.is_closing = False
        self.__init_authenticator_cls()
        self.max_conns_semaphore  = self.config.max_conns_semaphore
        self.connection_times = self.config.connection_times
        #print( self.max_conns_semaphore )

    def __init_authenticator_cls(self):
        for cls in AUTHENTICATORS_CLS_LIST:
            if cls.METHOD == self.config.AUTH_METHOD:
                self.authenticator_cls = cls

    def write(self, data):
        if not self.transport.is_closing():
            MAX_DL_SPEED=self.config.MAX_DL_SPEED
            if MAX_DL_SPEED:
                global DL
                DL.add_data( time.time() , len(data))
                DL_SPEED = DL.calculate_average_speed()
                if DL_SPEED > MAX_DL_SPEED :
                    SL=0.2
                    CHUNKSIZE=round( len(data) / 8 )
                    for data_chunk in [data[i:i+CHUNKSIZE] for i in range(0, len(data), CHUNKSIZE)]:
                        time.sleep(SL)
                        if not self.transport.is_closing():
                            self.transport.write(data_chunk)
                else:
                    self.transport.write(data)
            else:
                self.transport.write(data)

    def check_ratelimit_new_connection(self):
        if not self.config.RATE_LIMIT:
            return True
            
        now = time.time()
        one_minute_ago = now - 60

        # Remove old timestamps
        while self.connection_times and self.connection_times[0] < one_minute_ago:
            self.connection_times.popleft()

        if len(self.connection_times) < self.config.RATE_LIMIT:
            self.connection_times.append(now)
            return True
        return False

    def connection_made(self, transport):
        self.transport = transport
        self.peername = transport.get_extra_info("peername")
        self.stream_reader.set_transport(transport)
        loop = asyncio.get_event_loop()
        if self.check_ratelimit_new_connection():
            access_logger.debug( f'Connections/1min: {len( self.connection_times) }, from {self.peername}')
        else:
            access_logger.debug( f'Connections/1min: {len( self.connection_times) }, from {self.peername} OVER LIMIT')
            self.transport.close()
        self.negotiate_task = loop.create_task(self.negotiate())
        self.stage = self.STAGE_NEGOTIATE

        self.config.ACCESS_LOG and access_logger.debug(
            f"Made LocalTCP connection from {self.peername}. Remaining TCP conns limit: {self.max_conns_semaphore._value -1 }"
        )

    @staticmethod
    def gen_reply(
        rep: SocksRep,
        bind_host: str = "0.0.0.0",
        bind_port: int = 0,
    ) -> bytes:
        """Generate reply for negotiation."""

        VER, RSV = b"\x05", b"\x00"
        ATYP = get_socks_atyp_from_host(bind_host)
        if ATYP == SocksAtyp.IPV4:
            BND_ADDR = inet_pton(AF_INET, bind_host)
        elif ATYP == SocksAtyp.IPV6:
            BND_ADDR = inet_pton(AF_INET6, bind_host)
        else:
            BND_ADDR = len(bind_host).to_bytes(2, "big") + bind_host.encode("UTF-8")
        REP = rep.to_bytes(1, "big")
        ATYP = ATYP.to_bytes(1, "big")
        BND_PORT = int(bind_port).to_bytes(2, "big")
        return VER + REP + RSV + ATYP + BND_ADDR + BND_PORT


    async def negotiate(self):
        """Negotiate with the client. Find more detail in RFC1928.

        **Step 1.1**
        The client connects to the server, and sends a version
        identifier/method selection message: ::

            +----+----------+----------+
            |VER | NMETHODS | METHODS  |
            +----+----------+----------+
            | 1  |    1     | 1 to 255 |
            +----+----------+----------+

        **Step 1.2**
        The server selects from one of the methods given in METHODS, and
        sends a METHOD selection message: ::

            +----+--------+
            |VER | METHOD |
            +----+--------+
            | 1  |   1    |
            +----+--------+

        **Step 1.3**
        The client and the server enter a method-specific sub-negotiation.

        **Step 2.1**
        The client sends a socks request formed as follows: ::

            +----+-----+-------+------+----------+----------+
            |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            +----+-----+-------+------+----------+----------+
            | 1  |  1  | X'00' |  1   | Variable |    2     |
            +----+-----+-------+------+----------+----------+

        **Step 2.2**
        The server handles the command and returns a reply formed as
        follows: ::

            +----+-----+-------+------+----------+----------+
            |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
            +----+-----+-------+------+----------+----------+
            | 1  |  1  | X'00' |  1   | Variable |    2     |
            +----+-----+-------+------+----------+----------+

        """
        #print(f"sema Remaining TCP conns limit before ACQ: {self.max_conns_semaphore._value}" ,  id(self.max_conns_semaphore) )
        #print("sema acqing now",  id(self.max_conns_semaphore) )

        try:
            await asyncio.wait_for( self.max_conns_semaphore.acquire() , timeout=3)
        except asyncio.TimeoutError:
            self.config.ACCESS_LOG and access_logger.info(
                f"MAX_CONNS {self.config.MAX_CONNS} reached, closed connection."
                f"{self.peername}"
                )
            self.close(no_release_sema=True)

        #print(f"sema Remaining TCP conns limit after ACQ: {self.max_conns_semaphore._value}" ,  id(self.max_conns_semaphore) )

        try:
            # Step 1.1
            # The client sends a version identifier/method selection message.
            VER, NMETHODS = await self.stream_reader.readexactly(2)
            if VER != 5:
                self.transport.write(b"\x05\xff")
                raise NoVersionAllowed(f"Received unsupported socks version: {VER}")
            METHODS = set(await self.stream_reader.readexactly(NMETHODS))

            # Step 1.2
            # The server selects a method and sends selection message.

            CLIENT_SRC_ADDR = self.transport.get_extra_info("peername")[0]
            if CLIENT_SRC_ADDR in self.config.WHITELISTED_CLIENTS:
                self.authenticator_cls = NoAuthenticator

            authenticator = self.authenticator_cls(
                self.stream_reader, self.transport, self.config
            )
            METHOD = authenticator.select_method(METHODS)
            self.transport.write(b"\x05" + METHOD.to_bytes(1, "big"))
            if METHOD == 0xFF:
                raise NoAuthMethodAllowed("No authentication method is available")

            # Step 1.3
            # The client and the server enter a method-specific sub-negotiation.

            USERNAME = await authenticator.authenticate()

            self.config.ACCESS_LOG and access_logger.info(
                f'Authenticated user {USERNAME or "[no username specified]"} from { self.transport.get_extra_info("peername")[:2] }'
            )

            # Step 2.1
            # The client send a socks request.
            VER, CMD, RSV, ATYP = await self.stream_reader.readexactly(4)
            if ATYP == SocksAtyp.IPV4:
                DST_ADDR = inet_ntop(AF_INET, await self.stream_reader.readexactly(4))
            elif ATYP == SocksAtyp.DOMAIN:
                domain_len = int.from_bytes(
                    await self.stream_reader.readexactly(1), "big"
                )
                DST_ADDR = (await self.stream_reader.readexactly(domain_len)).decode()
            elif ATYP == SocksAtyp.IPV6:
                DST_ADDR = inet_ntop(AF_INET6, await self.stream_reader.readexactly(16))
            else:
                self.transport.write(
                    self.gen_reply(SocksRep.ADDRESS_TYPE_NOT_SUPPORTED)
                )
                raise NoAtypAllowed(f"Received unsupported ATYP value: {ATYP}")
            DST_PORT = int.from_bytes(await self.stream_reader.readexactly(2), "big")

            # Step 2.2
            # The server handles the command and returns a reply.
            if CMD == SocksCommand.CONNECT:
                self.config.ACCESS_LOG and access_logger.info(
                    f'Incoming Socks5 TCP request to {DST_ADDR}:{DST_PORT} from client {self.peername}'
                )

                try:
                    loop = asyncio.get_event_loop()

                    if ATYP == SocksAtyp.DOMAIN:
                        HNAME=DST_ADDR

                        if self.config.LDNS == DST_ADDR and DST_PORT==53:
                            pass
                        else:
                            if acl(self.config, HNAME) == -1:
                                raise NoAtypAllowed(f"ACL: Not allowed to call hostname {DST_ADDR}")

                        try:
                            dst_ip = ipaddress.ip_address(HNAME)
                            already_ip=1
                        except: 
                            already_ip=0

                        if already_ip:
                            self.config.ACCESS_LOG and access_logger.debug(f'we are asked to resolve hostname {HNAME}  but it is already IP, Socks client bug?')
                        else:
                            self.config.ACCESS_LOG and access_logger.debug(
                                f'[TCP] resolving remote name {HNAME}'
                            )
                            DST_ADDR = query(self.config.resolver, self.config,  HNAME )
                            if not DST_ADDR:
                                raise CommandExecError(f"Can't resolve hostname {HNAME}")
                            self.config.ACCESS_LOG and access_logger.debug(
                                f'[TCP] {HNAME} resolved to {DST_ADDR}'
                            )
                    else:
                        if self.config.LDNS == DST_ADDR and DST_PORT==53:
                            pass
                        else:
                            if self.config.DENY_RAW_IP_ADDRESSES == True:
                                raise NoAtypAllowed(f"ACL: triggered DENY_RAW_IP_ADDRESSES, not allowed to call raw IP {DST_ADDR}")
                            if acl(self.config, DST_ADDR) == -1:
                                raise NoAtypAllowed(f"TCP ACL: Not allowed to call IP {DST_ADDR}")

                    #print( [ self.config.LDNS, DST_ADDR, DST_PORT, self.config.RESOLVER ] )

                    if self.config.LDNS == DST_ADDR and DST_PORT==53 and self.config.RESOLVER :
                        access_logger.debug(f"TCP redirected to the Resolver {self.config.RESOLVER}")
                        DST_ADDR=self.config.RESOLVER
                    # Now DST_ADDR is Ipv4/Ipv6. 
                    task = loop.create_connection(
                        lambda: RemoteTCP(self, self.config), DST_ADDR, DST_PORT
                    )
                    remote_tcp_transport, remote_tcp = await asyncio.wait_for(task, 5)
                except ConnectionRefusedError:
                    self.transport.write(self.gen_reply(SocksRep.CONNECTION_REFUSED))
                    raise CommandExecError("Connection was refused") from None
                except socket.gaierror:
                    self.transport.write(self.gen_reply(SocksRep.HOST_UNREACHABLE))
                    raise CommandExecError("Host is unreachable") from None
                except Exception as e:
                    self.transport.write(
                        self.gen_reply(SocksRep.GENERAL_SOCKS_SERVER_FAILURE)
                    )
                    raise CommandExecError(
                        f"General socks server failure occurred {e}"
                    ) from None
                else:
                    self.remote_tcp = remote_tcp
                    bind_addr, bind_port = remote_tcp_transport.get_extra_info( "sockname")[:2]
                    self.transport.write(
                        self.gen_reply(SocksRep.SUCCEEDED, bind_addr, bind_port)
                    )
                    self.stage = self.STAGE_CONNECT

                    self.config.ACCESS_LOG and access_logger.info(
                        f"Established TCP stream between"
                        f" {self.peername} and {self.remote_tcp.peername}"
                    )
            elif CMD == SocksCommand.UDP_ASSOCIATE:
                self.config.ACCESS_LOG and access_logger.debug(
                    f'Incoming Socks5 Command UDP_ASSOCIATE from {self.peername}'
                )
                try:
                    loop = asyncio.get_event_loop()
                    if self.config.REWRITE_PORT_UDP_ASSOCIATE and int(self.config.MIN_PORT_UDP_ASSOCIATE) and int(self.config.MAX_PORT_UDP_ASSOCIATE):
                        local_udp_port_bind= find_free_udp_port( int(self.config.MIN_PORT_UDP_ASSOCIATE), int(self.config.MAX_PORT_UDP_ASSOCIATE) )
                    else:
                        local_udp_port_bind=0
                    self.config.ACCESS_LOG and access_logger.debug(
                        f"Chosen local UDP ASSOC port {local_udp_port_bind} for {self.peername}"
                    )
                    if self.config.CONE_NAT_FIX :
                        udp_hole_punch_dst=( self.peername[0], UDP_HOLE_PUNCH_DST_PORT  )
                        self.config.ACCESS_LOG and access_logger.debug(
                            f"Sending UDP hole punch (breaking through the local router), from local src port {local_udp_port_bind} to remote client { udp_hole_punch_dst }")
                        await loop.create_datagram_endpoint(
                            lambda: HolePunchProtocol( udp_hole_punch_dst ),
                            local_addr=('0.0.0.0', local_udp_port_bind),
                        )
                    client_id=self.peername[:2]
                    task = loop.create_datagram_endpoint(
                        lambda: LocalUDP((DST_ADDR, DST_PORT), self.config, client_id),
                        local_addr=("0.0.0.0", local_udp_port_bind),
                    )
                    local_udp_transport, local_udp = await asyncio.wait_for(task, 5)
                except Exception as e:
                    self.transport.write(
                        self.gen_reply(SocksRep.GENERAL_SOCKS_SERVER_FAILURE)
                    )
                    raise CommandExecError(
                        f"General socks server failure occurred {e}"
                    ) from None
                else:
                    self.local_udp = local_udp
                    bind_addr, bind_port = local_udp_transport.get_extra_info(
                        "sockname"
                    )
                    if self.config.REWRITE_UDP_ASSOCIATE_IP_TO :
                        bind_addr=self.config.REWRITE_UDP_ASSOCIATE_IP_TO  
                        self.config.ACCESS_LOG and access_logger.debug(
                            f"Rewritten Bind Address to {bind_addr} in UDP ASSOC response for {self.peername}"
                        )
                    self.transport.write(
                        self.gen_reply(SocksRep.SUCCEEDED, bind_addr, bind_port)
                    )
                    self.stage = self.STAGE_UDP_ASSOCIATE

                    self.config.ACCESS_LOG and access_logger.info(
                        f"Established UDP relay for Socks5 client {self.peername} "
                        f"at local side {bind_addr,bind_port}"
                    )
            else:
                self.transport.write(self.gen_reply(SocksRep.COMMAND_NOT_SUPPORTED))
                raise NoCommandAllowed(f"Unsupported CMD value: {CMD}")

        except (SocksException, ConnectionError, ValueError) as e:
            error_logger.warning(f"{e} during the negotiation with {self.peername}")
            self.close()
        finally:
            pass

    def data_received(self, data):
        if self.stage == self.STAGE_NEGOTIATE:
            self.stream_reader.feed_data(data)
        elif self.stage == self.STAGE_CONNECT:
            self.remote_tcp.write(data)
        elif self.stage == self.STAGE_UDP_ASSOCIATE:
            pass
        elif self.stage == self.STAGE_DESTROY:
            self.close()

    def eof_received(self):
        self.close()

    def pause_writing(self) -> None:
        try:
            self.remote_tcp.transport.pause_reading()
        except AttributeError:
            pass

    def resume_writing(self) -> None:
        self.remote_tcp.transport.resume_reading()

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self.close()

    def close(self, no_release_sema=False ):
        if self.is_closing:
            return
        self.stage = self.STAGE_DESTROY
        self.is_closing = True

        self.negotiate_task and self.negotiate_task.cancel()
        self.transport and self.transport.close()
        self.remote_tcp and self.remote_tcp.close()
        self.local_udp and self.local_udp.close()

        self.config.ACCESS_LOG and access_logger.debug(
            f"Closed LocalTCP connection from {self.peername}"
        )
        if no_release_sema:
            pass
            #print('close with NO sema release')
        else:
            self.max_conns_semaphore.release()
        #print("sema released", id(  self.max_conns_semaphore ) )
        #print(f"sema Remaining TCP conns limit after RELEASE : {self.max_conns_semaphore._value}" ,  id(self.max_conns_semaphore) )


class RemoteTCP(asyncio.Protocol):
    def __init__(self, local_tcp, config: Config):
        self.local_tcp = local_tcp
        self.config = config
        self.peername = None
        self.transport = None
        self.is_closing = False

    def write(self, data):
        if not self.transport.is_closing():
            self.transport.write(data)

    def connection_made(self, transport):
        self.transport = transport
        self.peername = transport.get_extra_info("peername")

        self.config.ACCESS_LOG and access_logger.debug(
            f"Made RemoteTCP connection to {self.peername}"
        )

    def data_received(self, data):
        self.local_tcp.write(data)

    def eof_received(self):
        self.close()

    def pause_writing(self) -> None:
        try:
            self.local_tcp.transport.pause_reading()
        except AttributeError:
            pass

    def resume_writing(self) -> None:
        self.local_tcp.transport.resume_reading()

    def connection_lost(self, exc):
        self.close()

    def close(self):
        if self.is_closing:
            return
        self.is_closing = True
        self.transport and self.transport.close()
        self.local_tcp.close()

        self.config.ACCESS_LOG and access_logger.debug(
            f"Closed RemoteTCP connection to {self.peername}"
        )


class LocalUDP(asyncio.DatagramProtocol):
    def __init__(self, host_port_limit: Tuple[str, int], config: Config, client_id ):
        self.host_port_limit = host_port_limit
        self.config = config
        self.transport = None
        self.sockname = None
        self.remote_udp_table = {}
        self.is_closing = False
        self.client_id=client_id

    def write(self, data, port_addr):
        if not self.transport.is_closing():
            self.transport.sendto(data, port_addr)

    def connection_made(self, transport) -> None:
        self.transport = transport
        self.sockname = transport.get_extra_info("sockname")

        self.config.ACCESS_LOG and access_logger.debug(
            f"Made LocalUDP endpoint at {self.sockname}, expecting Socks5 client there"
        )

    @staticmethod
    def parse_udp_request_header(data: bytes):
        """Parse the header of UDP request.

        Each UDP datagram carries a UDP request header formed as follows: ::

            +----+------+------+----------+----------+----------+
            |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
            +----+------+------+----------+----------+----------+
            | 2  |  1   |  1   | Variable |    2     | Variable |
            +----+------+------+----------+----------+----------+

        :param data: UDP datagram
        :return: A tuple containing header fields and header length
        :raise HeaderParseError: If parsing fails
        """

        length = 0
        RSV = data[length : length + 2]
        length += 2
        FRAG = data[length : length + 1]
        if int.from_bytes(FRAG, "big") != 0:
            raise HeaderParseError("Received unsupported FRAG value")
        length += 1
        ATYP = int.from_bytes(data[length : length + 1], "big")
        length += 1
        if ATYP == SocksAtyp.IPV4:
            ipv4 = data[length : length + 4]
            DST_ADDR = inet_ntop(AF_INET, ipv4)
            length += 4
        elif ATYP == SocksAtyp.DOMAIN:
            addr_len = int.from_bytes(data[length : length + 1], byteorder="big")
            length += 1
            DST_ADDR = data[length : length + addr_len].decode()
            length += addr_len
        elif ATYP == SocksAtyp.IPV6:
            ipv6 = data[length : length + 16]
            DST_ADDR = inet_ntop(AF_INET6, ipv6)
            length += 16
        else:
            raise HeaderParseError(f"Received unsupported ATYP value: {ATYP}")
        DST_PORT = int.from_bytes(data[length : length + 2], "big")
        length += 2
        if length > len(data):
            raise HeaderParseError("Header is too short")

        return RSV, FRAG, ATYP, DST_ADDR, DST_PORT, length

    def datagram_received(self, data: bytes, local_host_port: Tuple[str, int]):
        cond1 = self.host_port_limit in itertools.product(
            ("0.0.0.0", "::", local_host_port[0]), (0, local_host_port[1])
        )
        cond2 = self.config.STRICT == False
        if not cond1 and not cond2:
            return

        loop = asyncio.get_event_loop()
        loop.create_task(self.relay_task(data, local_host_port))

    async def relay_task(self, data: bytes, local_host_port: Tuple[str, int]):
        try:
            (
                RSV,
                FRAG,
                ATYP,
                DST_ADDR,
                DST_PORT,
                header_length,
            ) = self.parse_udp_request_header(data)

            self.config.ACCESS_LOG and access_logger.info(
                f'Incoming Socks5 UDP request to {DST_ADDR}:{DST_PORT} from client {self.client_id}'
            )

            if self.config.LDNS == DST_ADDR and DST_PORT==53 and self.config.RESOLVER :
                access_logger.debug(f"UDP redirected to the Resolver {self.config.RESOLVER}")
                DST_ADDR=self.config.RESOLVER

            if ATYP == SocksAtyp.DOMAIN:
                HNAME=DST_ADDR
                if acl(self.config, HNAME) == -1:
                    raise NoAtypAllowed(f"ACL: Not allowed to call hostname {DST_ADDR}")
                self.config.ACCESS_LOG and access_logger.debug(
                    f'[UDP] resolving remote name {HNAME}'
                )
                DST_ADDR = query(self.config.resolver, self.config,  HNAME )
                if not DST_ADDR:
                    raise HeaderParseError(f"Can't resolve hostname {HNAME}")
                self.config.ACCESS_LOG and access_logger.debug(
                    f'[UDP] {HNAME} resolved to {DST_ADDR}'
                )
            else:
                #print([self.config.LDNS , DST_ADDR, DST_PORT ])
                if self.config.LDNS == DST_ADDR and DST_PORT==53:
                    pass
                else:
                    if acl(self.config, DST_ADDR) == -1:
                        raise NoAtypAllowed(f"UDP ACL: Not allowed to call IP {DST_ADDR}")
                    if self.config.DENY_RAW_IP_ADDRESSES == True:
                        raise NoAtypAllowed(f"ACL: triggered DENY_RAW_IP_ADDRESSES, not allowed to call raw IP {DST_ADDR}")

            if local_host_port not in self.remote_udp_table:
                if ipaddress.ip_address(DST_ADDR).version==4:
                    laddr = ("0.0.0.0", 0)
                else: 
                    laddr = ("::", 0)
                loop = asyncio.get_event_loop()
                task = loop.create_datagram_endpoint(
                    lambda: RemoteUDP(self, local_host_port, self.config),
                    local_addr=("0.0.0.0", 0),
                )
                _, remote_udp = await asyncio.wait_for(task, 5)
                self.remote_udp_table[local_host_port] = remote_udp
            remote_udp = self.remote_udp_table[local_host_port]
            remote_udp.write(data[header_length:], (DST_ADDR, DST_PORT))
        except Exception as e:
            error_logger.warning(
                f"{e} during relaying the request from {local_host_port}"
            )
            return

    def close(self):
        if self.is_closing:
            return
        self.is_closing = True
        self.transport and self.transport.close()
        for local_host_port in self.remote_udp_table:
            self.remote_udp_table[local_host_port].close()

        self.config.ACCESS_LOG and access_logger.debug(
            f"Closed LocalUDP endpoint at {self.sockname}"
        )


class RemoteUDP(asyncio.DatagramProtocol):
    def __init__(self, local_udp, local_host_port, config: Config):
        self.local_udp = local_udp
        self.local_host_port = local_host_port
        self.config = config
        self.transport = None
        self.sockname = None
        self.is_closing = False

    def connection_made(self, transport) -> None:
        self.transport = transport
        self.sockname = transport.get_extra_info("sockname")

        self.config.ACCESS_LOG and access_logger.debug(
            f"Made RemoteUDP endpoint at {self.sockname}"
        )

    def write(self, data, host_port):
        if not self.transport.is_closing():
            self.transport.sendto(data, host_port)

    @staticmethod
    def gen_udp_reply_header(remote_host_port: Tuple[str, int], config):
        """Generate the header of UDP reply.

        When a UDP relay server receives a reply datagram from a remote
        host, it MUST encapsulate that datagram using the UDP request
        header: ::

            +----+------+------+----------+----------+----------+
            |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
            +----+------+------+----------+----------+----------+
            | 2  |  1   |  1   | Variable |    2     | Variable |
            +----+------+------+----------+----------+----------+

        and any authentication-method-dependent encapsulation.

        :param remote_host_port: A tuple of host and port
        :return: The bytes of the generated header
        """

        RSV, FRAG = b"\x00\x00", b"\x00"
        remote_host, remote_port = remote_host_port
        ATYP = get_socks_atyp_from_host(remote_host)
        if ATYP == SocksAtyp.IPV4:
            DST_ADDR = inet_pton(AF_INET, remote_host)
        elif ATYP == SocksAtyp.IPV6:
            DST_ADDR = inet_pton(AF_INET6, remote_host)
        else:  # ATYP == SocksAtyp.DOMAIN
            DST_ADDR = len(remote_host).to_bytes(1, "big") + remote_host.encode("UTF-8")
        ATYP = ATYP.to_bytes(1, "big")
        DST_PORT = remote_port.to_bytes(2, "big")
        config.ACCESS_LOG and access_logger.debug(
            f'Outcoming UDP request to {remote_host}:{remote_port}'
        )
        return RSV + FRAG + ATYP + DST_ADDR + DST_PORT

    def datagram_received(self, data: bytes, remote_host_port: Tuple[str, int]) -> None:
        try:
            header = self.gen_udp_reply_header(remote_host_port, self.config)
            self.local_udp.write(header + data, self.local_host_port)
        except Exception as e:
            error_logger.warning(
                f"{e} during relaying the response from {remote_host_port}"
            )
            return

    def close(self):
        if self.is_closing:
            return
        self.is_closing = True
        self.transport and self.transport.close()
        self.local_udp = None

        self.config.ACCESS_LOG and access_logger.debug(
            f"Closed RemoteUDP endpoint at {self.sockname}"
        )

    def error_received(self, exc):
        self.close()

    def connection_lost(self, exc):
        self.close()
