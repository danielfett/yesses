import nmap
import logging
from yesses.module import YModule

log = logging.getLogger('scan/ports')

class Ports(YModule):
    """Uses `nmap` to scan for open ports.
    """
    INPUTS = {
        "ips": {
            "required_keys": [
                "ip"
            ],
            "description": "Required. IP range to scan (e.g., `use IPs`)",
            "unwrap": True,
        },
        "protocols": {
            "required_keys": None,
            "description": "List of protocols (`udp`, `tcp`,...) in nmap's notations to scan. (Default: `tcp`)",
            "default": ['tcp'],
        },
        "ports": {
            "required_keys": None,
            "description": "Port range in nmap notation (e.g., '22,80,443-445'); default (None): 1000 most common ports as defined by nmap.",
            "default": None,
        }
    }

    OUTPUTS = {
        "Host-Ports": {
            "provided_keys": [
                "ip",
                "protocol",
                "port"
            ],
            "description": "Each open port on a scanned IP"
        },
        "*-IPs": {
            "provided_keys": [
                "ip"
            ],
            "description": "For certain protocols (SSH, HTTP, HTTPS), a list of IPs that have this port open"
        },
        "Other-Port-IPs": {
            "provided_keys": None,
            "description": "List of IPs that have any other ports open."
        }
    }

        
    default_arguments = ['-T4', '-n', '-Pn']
    protocol_arguments = {
        'udp': '-sU',
        'tcp': '-sT'
    }
    named_ports = {
        'SSH': 22,
        'HTTP': 80,
        'HTTPS': 443
    }

    def run(self):
        for ip in self.ips:
            self.results['Host-Ports'] += self.scan(ip)
            
        for protocol, port in self.named_ports.items():
            #self.results[f'{protocol}-Ports'] = [x for x in self.results['Host-Ports'] if x[2] == port]
            iplist = list(set(x[0] for x in self.results['Host-Ports'] if x[2] == port))
            self.results[f'{protocol}-IPs'] = [{'ip': i} for i in iplist]

        iplist = list(set(x[0] for x in self.results['Host-Ports'] if x[2] not in self.named_ports.values()))
        self.results[f'Other-Port-IPs'] = [{'ip': i} for i in iplist]
            

    def scan(self, ip):
        log.info(f"Scanning {ip}.")
        args = [self.protocol_arguments[p] for p in self.protocols]
        if ':' in ip: # poor man's IPv6 detection
            args.append('-6')
        args += self.default_arguments
        
        scanner = nmap.PortScanner()
        scanner.scan(ip, self.ports, arguments=' '.join(args))
        return [
            {'ip': ip, 'protocol': protocol, 'port': port}
            for protocol in self.protocols
            for (port, data) in scanner[ip].get(protocol, {}).items() if data['state'] == 'open'
            ]
    
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    import sys
    d = ScanPorts(sys.argv[1].split(','), sys.argv[2:])
    print (d.run())
