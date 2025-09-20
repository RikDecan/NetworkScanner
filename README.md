# Advanced Python Network Scanner

A powerful and feature-rich network scanner built in Python, designed for ethical network exploration and analysis.

## Features

- **Device identification:** IP addresses, MAC addresses, vendors, hostnames, and NetBIOS names.  
- **Port scanning:** Common TCP and UDP ports, with automatic detection of open services.  
- **Service enumeration:** HTTP server headers, SMB shares, and more.  
- **Ping/ICMP detection:** Identify active devices and monitor network responsiveness.  
- **Enhanced UX:** Rich, colorized console output with summary statistics and tables.  
- **Concurrent scanning:** Fully asynchronous for faster network exploration.  

## Built With

- [Python 3.12+](https://www.python.org/)  
- [Scapy](https://scapy.net/)  
- [nfstream](https://github.com/nfstream/nfstream)  
- [aiohttp](https://docs.aiohttp.org/)  
- [rich](https://github.com/Textualize/rich)  
- [mac-vendor-lookup](https://pypi.org/project/mac-vendor-lookup/)  
- [smbprotocol](https://pypi.org/project/smbprotocol/)  

## Usage

1. Clone the repository:  
   ```bash
   git clone https://github.com/yourusername/NetworkScanner.git
   cd NetworkScanner
