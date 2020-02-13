import nmap
import logging
from yesses.module import YModule, YExample

log = logging.getLogger("scan/ports")


class Ports(YModule):
    """Uses `nmap` to scan for open ports.
    """

    DEFAULT_PROTOCOL_ARGUMENTS = [
        {"protocol": "udp", "arguments": "-sU"},
        {"protocol": "tcp", "arguments": "-sT"},
    ]

    DEFAULT_NAMED_PORTS = [
        {"name": "SSH", "port": 22},
        {"name": "HTTP", "port": 80},
        {"name": "HTTPS", "port": 443},
    ]

    INPUTS = {
        "ips": {
            "required_keys": ["ip"],
            "description": "Required. IP range to scan (e.g., `use IPs`)",
            "unwrap": True,
        },
        "protocols": {
            "required_keys": None,
            "description": "List of protocols (`udp`, `tcp`,...) in nmap's notations to scan. (Default: `tcp`)",
            "default": ["tcp"],
        },
        "ports": {
            "required_keys": None,
            "description": "Port range in nmap notation (e.g., '22,80,443-445'); default (None): 1000 most common ports as defined by nmap.",
            "default": None,
        },
        "named_ports": {
            "required_keys": ["name", "port"],
            "description": "A mapping of names to ports. This can be used to control the output of this module.",
            "default": DEFAULT_NAMED_PORTS,
        },
        "protocol_arguments": {
            "required_keys": ["protocol", "arguments"],
            "description": "Command-line arguments to provide to nmap when scanning for a specific protocol.",
            "default": DEFAULT_PROTOCOL_ARGUMENTS,
        },
    }

    OUTPUTS = {
        "Host-Ports": {
            "provided_keys": ["ip", "protocol", "port"],
            "description": "Each open port on a scanned IP (with IP, protocol, and port)",
        },
        "*-Ports": {
            "provided_keys": ["ip", "protocol", "port"],
            "description": "For certain protocols (SSH, HTTP, HTTPS), a list of hosts that have this port open (with IP, protocol, and port)",
        },
        "Other-Port-IPs": {
            "provided_keys": None,
            "description": "List of IPs that have any other ports open.",
        },
    }

    EXAMPLES = [
        YExample(
            "scan ports on Google DNS server",
            """
  - scan Ports:
      ips: 
        - ip: '8.8.8.8'
      protocols: ['tcp']
    find:
      - Host-Ports
      - HTTPS-Ports
      - Other-Port-IPs
    expect:
      - no Host-Ports, otherwise alert high
""",
        )
    ]

    default_arguments = ["-T4", "-n", "-Pn"]

    def run(self):
        for ip in self.ips:
            self.results["Host-Ports"] += self.scan(ip)

        known_ports = []
        for namedport in self.named_ports:
            port = namedport["port"]
            name = namedport["name"]
            known_ports.append(port)
            self.results[f"{name}-Ports"] = [
                x for x in self.results["Host-Ports"] if x["port"] == port
            ]
            # iplist = list(set(x['ip'] for x in self.results['Host-Ports'] if x['port'] == port))
            # self.results[f'{protocol}-IPs'] = [{'ip': i} for i in iplist]

        iplist = list(
            set(
                x["ip"]
                for x in self.results["Host-Ports"]
                if x["port"] not in known_ports
            )
        )
        self.results["Other-Port-IPs"] = [{"ip": i} for i in iplist]

    def scan(self, ip):
        log.info(f"Scanning {ip}.")
        args = [
            pa["arguments"]
            for pa in self.protocol_arguments
            if pa["protocol"] in self.protocols
        ]
        if ":" in ip:  # poor man's IPv6 detection
            args.append("-6")
        args += self.default_arguments

        scanner = nmap.PortScanner()
        scanner.scan(ip, self.ports, arguments=" ".join(args))
        return [
            {"ip": ip, "protocol": protocol, "port": port}
            for protocol in self.protocols
            for (port, data) in scanner[ip].get(protocol, {}).items()
            if data["state"] == "open"
        ]


if __name__ == "__main__":
    Ports.selftest()
