import logging
import socket
import uuid
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
import sys
import os

import aiohttp
import asyncio
from scapy.all import ARP, Ether, IP, UDP, ICMP, sr1, srp, conf
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
import nfstream
from mac_vendor_lookup import MacLookup
import smbprotocol.connection
from smbprotocol.session import Session
from smbprotocol.exceptions import SMBException

# Redirect stderr to suppress scapy warnings about MAC addresses
original_stderr = sys.stderr
sys.stderr = open(os.devnull, 'w')

# Configure logging to file only, not to console
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='network_scan.log'
)
logger = logging.getLogger(__name__)

# Reduce scapy verbosity to absolute minimum
conf.verb = 0
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

@dataclass
class DeviceInfo:
    """Store information about discovered network devices"""
    ip_address: str
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    open_ports: Set[int] = None
    open_udp_ports: Set[int] = None
    http_banner: Optional[str] = None
    smb_shares: List[str] = None
    netbios_name: Optional[str] = None
    ping_response: bool = False
    last_seen: datetime = None

    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = set()
        if self.open_udp_ports is None:
            self.open_udp_ports = set()
        if self.smb_shares is None:
            self.smb_shares = []
        self.last_seen = datetime.now()

class NetworkScanner:
    def __init__(self, subnet: str, interface: str = None):
        self.subnet = subnet
        self.interface = interface
        self.devices: Dict[str, DeviceInfo] = {}
        self.mac_lookup = MacLookup()
        self.console = Console()
        self.common_tcp_ports = [22, 80, 443, 3389, 445]
        self.common_udp_ports = [53, 67, 123, 137, 138, 161]  # DNS, DHCP, NTP, NetBIOS, SNMP

        # Summary statistics that will be used later
        self.stats = {
            "total_devices": 0,
            "ping_responded": 0,
            "total_tcp_ports": 0,
            "total_udp_ports": 0
        }

    async def scan_network(self):
        """Main scanning function that coordinates all scan types"""
        try:
            # Start with ARP scan for initial device discovery
            self.arp_scan()

            # Also scan with ICMP to find devices that might not respond to ARP
            await self.ping_scan()

            # For each discovered device, perform additional scans
            tasks = []
            for ip, device in list(self.devices.items()):
                tasks.append(self.check_tcp_ports(ip))
                tasks.append(self.check_udp_ports(ip))
                tasks.append(self.get_hostname(ip))
                tasks.append(self.check_smb(ip))
                tasks.append(self.http_banner_grab(ip))
                tasks.append(self.netbios_scan(ip))

            await asyncio.gather(*tasks)

            # Calculate final statistics
            self.calc_statistics()

        except Exception as e:
            logger.error(f"Error during network scan: {e}")
            raise

    def arp_scan(self):
        """Perform ARP scan to discover devices"""
        try:
            arp = ARP(pdst=self.subnet)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            logger.info(f"Starting ARP scan for subnet {self.subnet}")
            result = srp(packet, timeout=3, verbose=False, iface=self.interface)[0]

            for sent, received in result:
                ip = received.psrc
                mac = received.hwsrc

                # Create or update device info
                if ip in self.devices:
                    self.devices[ip].mac_address = mac
                    self.devices[ip].last_seen = datetime.now()
                else:
                    device_info = DeviceInfo(ip_address=ip, mac_address=mac)
                    self.devices[ip] = device_info

                # Lookup vendor information
                try:
                    self.devices[ip].vendor = self.mac_lookup.lookup(mac)
                except Exception as e:
                    logger.warning(f"Could not lookup vendor for MAC {mac}: {e}")

        except Exception as e:
            logger.error(f"Error during ARP scan: {e}")
            raise

    async def ping_scan(self):
        """Perform ICMP echo scan to discover devices"""
        logger.info(f"Starting ICMP ping scan for subnet {self.subnet}")

        # Extract network range from CIDR notation
        if '/' in self.subnet:
            network_part = self.subnet.split('/')[0]
            prefix = int(self.subnet.split('/')[1])

            # Simple way to handle /24 networks common in home/small office
            if prefix == 24:
                base_ip = '.'.join(network_part.split('.')[:3]) + '.'
                tasks = []

                for i in range(1, 255):
                    ip = f"{base_ip}{i}"
                    tasks.append(self.ping_host(ip))

                await asyncio.gather(*tasks)
            else:
                logger.warning(f"ICMP scan for non-/24 networks not fully implemented: {self.subnet}")
        else:
            # Single IP address
            await self.ping_host(self.subnet)

    async def ping_host(self, ip: str):
        """Ping individual host using ICMP"""
        try:
            # Use scapy for platform-independent ICMP echo
            packet = IP(dst=ip)/ICMP()
            response = await asyncio.to_thread(sr1, packet, timeout=2, verbose=0)

            if response:
                logger.debug(f"Received ICMP response from {ip}")

                # Create or update device info
                if ip in self.devices:
                    self.devices[ip].ping_response = True
                    self.devices[ip].last_seen = datetime.now()
                else:
                    device_info = DeviceInfo(ip_address=ip, ping_response=True)
                    self.devices[ip] = device_info

                return True
        except Exception as e:
            logger.debug(f"Error pinging {ip}: {e}")

        return False

    async def check_tcp_ports(self, ip: str):
        """Check common TCP ports"""
        tasks = []
        for port in self.common_tcp_ports:
            tasks.append(self.check_tcp_port(ip, port))

        await asyncio.gather(*tasks)

    async def check_tcp_port(self, ip: str, port: int):
        """Check if a TCP port is open"""
        try:
            # Use asyncio for faster concurrent port scanning
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=1.0)

            if ip in self.devices:
                self.devices[ip].open_ports.add(port)

            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass

            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False
        except Exception as e:
            logger.debug(f"Error checking TCP port {port} on {ip}: {e}")
            return False

    async def check_udp_ports(self, ip: str):
        """Check common UDP ports"""
        tasks = []
        for port in self.common_udp_ports:
            tasks.append(self.check_udp_port(ip, port))

        await asyncio.gather(*tasks)

    async def check_udp_port(self, ip: str, port: int):
        """Check if a UDP port is open or filtered"""
        try:
            # UDP scanning is tricky - we'll use a combination of approaches
            # 1. For common services, we'll send appropriate probe packets
            # 2. For other ports, we'll use simple heuristics

            # Send a UDP packet and check for ICMP unreachable response
            # If no ICMP unreachable is received, the port might be open
            packet = IP(dst=ip)/UDP(dport=port)

            # We need to use sr1 function from scapy in a thread to avoid blocking
            response = await asyncio.to_thread(
                sr1,
                packet,
                timeout=1,
                verbose=0
            )

            # If we get no response, the port might be open or filtered
            # If we get an ICMP unreachable error, the port is likely closed
            if response is None or not (response.haslayer('ICMP') and
                                        response.getlayer('ICMP').type == 3 and
                                        response.getlayer('ICMP').code in [1, 2, 3, 9, 10, 13]):
                if ip in self.devices:
                    self.devices[ip].open_udp_ports.add(port)
                return True

            return False

        except Exception as e:
            logger.debug(f"Error checking UDP port {port} on {ip}: {e}")
            return False

    async def get_hostname(self, ip: str):
        """Perform reverse DNS lookup"""
        try:
            hostname = await asyncio.to_thread(socket.gethostbyaddr, ip)
            if ip in self.devices:
                self.devices[ip].hostname = hostname[0]
        except socket.herror:
            logger.debug(f"Could not resolve hostname for {ip}")
        except Exception as e:
            logger.error(f"Error getting hostname for {ip}: {e}")

    async def check_smb(self, ip: str):
        """Check for SMB shares and information"""
        if ip not in self.devices:
            return

        # Skip if port 445 is not open
        if 445 not in self.devices[ip].open_ports:
            return

        try:
            # Run SMB discovery in separate thread to avoid blocking
            def check_smb_sync():
                connection = smbprotocol.connection.Connection(uuid.uuid4(), ip, 445)
                connection.connect()

                session = Session(connection, username="guest", password="")
                try:
                    session.connect()

                    # Get share list (simplified for example)
                    tree = session.tree_connect("IPC$")
                    shares = ["IPC$"]

                    tree.disconnect()
                    connection.disconnect()
                    return shares
                except:
                    connection.disconnect()
                    return []

            shares = await asyncio.to_thread(check_smb_sync)
            if shares and ip in self.devices:
                self.devices[ip].smb_shares = shares

        except Exception as e:
            logger.debug(f"SMB connection failed for {ip}: {e}")

    async def http_banner_grab(self, ip: str):
        """Grab HTTP server headers"""
        if ip not in self.devices:
            return

        if 80 in self.devices[ip].open_ports or 443 in self.devices[ip].open_ports:
            try:
                # Try to connect to the HTTP server
                async with aiohttp.ClientSession() as session:
                    for protocol, port in [('http', 80), ('https', 443)]:
                        if port not in self.devices[ip].open_ports:
                            continue

                        try:
                            async with session.get(
                                    f"{protocol}://{ip}",
                                    timeout=aiohttp.ClientTimeout(total=2),
                                    ssl=False
                            ) as response:
                                server = response.headers.get('Server', '')
                                if server and ip in self.devices:
                                    self.devices[ip].http_banner = server
                                    break
                        except Exception as e:
                            logger.debug(f"Error connecting to {protocol}://{ip}: {e}")
            except Exception as e:
                logger.error(f"Error grabbing HTTP banner for {ip}: {e}")

    async def netbios_scan(self, ip: str):
        """Scan for NetBIOS information using direct socket connection"""
        if ip not in self.devices:
            return

        NETBIOS_NAMESERVICE_PORT = 137

        try:
            # NetBIOS name query
            name_query = bytearray([
                0x00, 0x00,             # Transaction ID
                0x00, 0x10,             # Flags (Standard query)
                0x00, 0x01,             # Questions
                0x00, 0x00,             # Answer RRs
                0x00, 0x00,             # Authority RRs
                0x00, 0x00,             # Additional RRs
                0x20, 0x43, 0x4b,       # Name: ' CK'
                0x41, 0x41, 0x41,       # 'AAA'
                0x41, 0x41, 0x41,       # 'AAA'
                0x41, 0x41, 0x41,       # 'AAA'
                0x41, 0x41, 0x41,       # 'AAA'
                0x41, 0x00,             # 'A'
                0x00, 0x21,             # Type: NBSTAT
                0x00, 0x01              # Class: IN
            ])

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.0)

            # Send the NetBIOS name query
            sock.sendto(name_query, (ip, NETBIOS_NAMESERVICE_PORT))

            # Receive the response
            try:
                data, _ = sock.recvfrom(4096)

                # Very basic parsing - extract the NetBIOS name
                if len(data) > 56:
                    # The number of names is at offset 56
                    num_names = data[56]

                    if num_names > 0 and len(data) >= 58:
                        # First name starts at offset 57
                        name_length = 15  # NetBIOS names are 15 chars + 1 type byte
                        name = data[57:57+name_length].decode('ascii', errors='ignore').strip()

                        if ip in self.devices:
                            self.devices[ip].netbios_name = name
                            logger.info(f"Found NetBIOS name for {ip}: {name}")
            except socket.timeout:
                logger.debug(f"NetBIOS timeout for {ip}")
            finally:
                sock.close()

        except Exception as e:
            logger.debug(f"Error during NetBIOS scan for {ip}: {e}")

    def calc_statistics(self):
        """Calculate summary statistics"""
        self.stats["total_devices"] = len(self.devices)

        for device in self.devices.values():
            if device.ping_response:
                self.stats["ping_responded"] += 1
            self.stats["total_tcp_ports"] += len(device.open_ports)
            self.stats["total_udp_ports"] += len(device.open_udp_ports)

    def display_results(self):
        """Display scan results in a formatted table with summary stats outside the table"""
        # Create and display the main table
        table = Table(title="Network Scan Results")

        table.add_column("IP Address", style="cyan")
        table.add_column("MAC Address", style="magenta")
        table.add_column("Vendor", style="green")
        table.add_column("Hostname", style="blue")
        table.add_column("NetBIOS", style="bright_green")
        table.add_column("TCP Ports", style="red")
        table.add_column("UDP Ports", style="yellow")
        table.add_column("Ping", style="bright_blue")
        table.add_column("HTTP Server", style="bright_magenta")
        table.add_column("SMB Shares", style="white")

        for device in self.devices.values():
            table.add_row(
                device.ip_address,
                device.mac_address or "N/A",
                device.vendor or "N/A",
                device.hostname or "N/A",
                device.netbios_name or "N/A",
                ", ".join(map(str, device.open_ports)) or "None",
                ", ".join(map(str, device.open_udp_ports)) or "None",
                "✓" if device.ping_response else "✗",
                device.http_banner or "N/A",
                ", ".join(device.smb_shares) or "None"
            )

        self.console.print(table)

        # Print summary statistics outside the table
        self.console.print()  # Add empty line for spacing
        self.console.print(f"[bold]Summary Statistics:[/bold]")
        self.console.print(f"Total Devices: {self.stats['total_devices']}")
        self.console.print(f"ICMP Responded: {self.stats['ping_responded']}")
        self.console.print(f"TCP Ports Open: {self.stats['total_tcp_ports']}")
        self.console.print(f"UDP Ports Open: {self.stats['total_udp_ports']}")
        self.console.print()  # Add empty line for spacing

        logger.info(f"Total devices detected: {self.stats['total_devices']}")
        logger.info(f"Devices that responded to ping: {self.stats['ping_responded']}")
        logger.info(f"Total TCP ports open: {self.stats['total_tcp_ports']}")
        logger.info(f"Total UDP ports open: {self.stats['total_udp_ports']}")


async def main():
    # Example usage - change to your subnet and interface
    scanner = NetworkScanner("10.0.20.0/24", "eth0")
    
    # Create a custom progress display that doesn't update as frequently
    print("Scanning network... This may take a few minutes.")
    
    try:
        await scanner.scan_network()
        print("Scan complete.")
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        print(f"Scan failed: {e}")
        return

    # Restore stderr for table display
    sys.stderr = original_stderr
    scanner.display_results()


if __name__ == "__main__":
    asyncio.run(main())
