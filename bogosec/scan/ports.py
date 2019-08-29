import nmap
import logging

log = logging.getLogger('scan/ports')

class Ports:
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
    
    def __init__(self, ips, protocols=['tcp'], ports=None):
        self.ips = ips
        self.protocols = protocols
        self.ports = ports
        log.info(f'Using IPs: {ips!r} and protocols: {protocols!r}')

    def run(self):
        results = {'Host-Ports':[], 'Other-Ports':[]}
        for ip in self.ips:
            results['Host-Ports'] += self.scan(ip)
            
        for protocol, port in self.named_ports.items():
            #results[f'{protocol}-Ports'] = [x for x in results['Host-Ports'] if x[2] == port]
            results[f'{protocol}-IPs'] = list(set(x[0] for x in results['Host-Ports'] if x[2] == port))

        results[f'Other-Port-IPs'] = list(set(x[0] for x in results['Host-Ports'] if x[2] not in self.named_ports.values()))
            
        return results

    def scan(self, ip):
        log.info(f"Scanning {ip}.")
        args = [self.protocol_arguments[p] for p in self.protocols]
        if ':' in ip: # poor man's IPv6 detection
            args.append('-6')
        args += self.default_arguments
        
        scanner = nmap.PortScanner()
        scanner.scan(ip, self.ports, arguments=' '.join(args))
        return [
            (ip, protocol, port)
            for protocol in self.protocols
            for (port, data) in scanner[ip].get(protocol, {}).items() if data['state'] == 'open'
            ]
    
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    import sys
    d = ScanPorts(sys.argv[1].split(','), sys.argv[2:])
    print (d.run())
