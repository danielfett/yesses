import nmap
import logging
from yesses.module import unwrap_key, YModule

log = logging.getLogger('scan/ports')

class Ports(YModule):
    """Uses `nmap` to scan for open ports.
    """

    INPUTS = [
        ('ips', ['ip'], 'Required. IP range to scan (e.g., `use IPs`)'),
        ('protocols', None, 'List of protocols (`udp`, `tcp`,...) in nmap\'s notations to scan. (Default: `tcp`)'),
        ('ports', None, 'Port range in nmap notation (e.g., \'22,80,443-445\'); default: 0-65535'),
    ]

    OUTPUTS = [
        ('Host-Ports', ['ip', 'protocol', 'port'], 'Each open port on a scanned IP'),
        ('*-IPs', ['ip'], 'For certain protocols (SSH, HTTP, HTTPS), a list of IPs that have this port open'),
        ('Other-Port-IPs', None, 'List of IPs that have any other ports open.'),
    ]
        
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

    @unwrap_key('ips', 'ip')
    def __init__(self, step, ips, protocols=['tcp'], ports=None):
        self.step = step
        self.ips = ips
        self.protocols = protocols
        self.ports = ports
        log.info(f'Using IPs: {ips!r} and protocols: {protocols!r}')

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
