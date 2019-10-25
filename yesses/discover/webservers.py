import logging
from yesses.utils import force_ip_connection
import requests
from yesses.module import YModule, YExample

log = logging.getLogger('scan/webservers')


class Webservers(YModule):
    """Scans an IP range for web servers (on standard HTTP and HTTPs
ports); combines a list of IPs with a list of domains to use for the
Host header in web requests.

    """

    PORTS = [{"port": 80}, {"port": 443}]

    INPUTS = {
        "ips": {
            "required_keys": [
                "ip",
                "port"
            ],
            "description": "IPs and ports to scan (e.g. from the Ports module: Host-Ports)",
        },
        "domains": {
            "required_keys": [
                "domain"
            ],
            "description": "Domain names to try on these IPs",
            "unwrap": True,
        },
        "ports": {
            "required_keys": [
                "port"
            ],
            "description": "Ports to look for web servers",
            "default": PORTS,
            "unwrap": True,
        }
    }

    OUTPUTS = {
        "Insecure-Origins": {
            "provided_keys": [
                "domain",
                "url",
                "ip"
            ],
            "description": "HTTP origins"
        },
        "Secure-Origins": {
            "provided_keys": [
                "domain",
                "url",
                "ip"
            ],
            "description": "as above, but for HTTPS"
        },
        "TLS-Domains": {
            "provided_keys": [
                "domain"
            ],
            "description": "List of domains with HTTPS servers"
        }
    }

    EXAMPLES = [
        YExample("detect webservers on example.com", """
  - discover Webservers:
      ips: 
        - ip: '93.184.216.34'
          port: 80
        - ip: '93.184.216.34'
          port: 443
        - ip: '2606:2800:220:1:248:1893:25c8:1946'
          port: 80
        - ip: '2606:2800:220:1:248:1893:25c8:1946'
          port: 443
      domains:
        - domain: example.com
        - domain: dev.example.com
      ports:
        - port: 80
        - port: 443
    find:
      - Insecure-Origins
      - Secure-Origins
      - TLS-Domains
""")
    ]

    def run(self):
        output_insecure = []
        output_secure = []
        tls_domains = []
        for ip in self.ips:
            # just check a port if it is open and in the list of passed ports
            if ip['port'] in self.ports:
                for domain in self.domains:
                    for protocol in ('http', 'https'):
                        with force_ip_connection(domain, ip['ip']):
                            url = f"{protocol}://{domain}:{ip['port']}/"
                            try:
                                result = requests.get(url, timeout=10)
                            except requests.exceptions.RequestException as e:
                                log.debug(f"Exception {e} on {url}, ip={ip['ip']}")
                            else:
                                el = {'url': url, 'domain': domain, 'ip': ip['ip']}
                                if protocol == 'https':
                                    output_secure.append(el)
                                    dom = {'domain': domain}
                                    if not dom in tls_domains:
                                        tls_domains.append(dom)
                                else:
                                    output_insecure.append(el)
                                log.info(f"Found webserver {url} on {ip['ip']}")
        self.results['Insecure-Origins'] = output_insecure
        self.results['Secure-Origins'] = output_secure
        self.results['TLS-Domains'] = tls_domains


if __name__ == "__main__":
    Webservers.selftest()
