import nmap
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
    
    INPUTS = {
        "ips": {
            "required_keys": [
                "ip"
            ],
            "description": "IP range to scan (e.g., `use HTTP-IPs and HTTPS-IPs`)",
            "unwrap": True,
        },
        "domains": {
            "required_keys": [
                "domain"
            ],
            "description": "Domain names to try on these IPs",
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
        - ip: '2606:2800:220:1:248:1893:25c8:1946'
      domains:
        - domain: example.com
        - domain: dev.example.com
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
            for domain in self.domains:
                for protocol in ('http', 'https'):
                    with force_ip_connection(domain, ip):
                        url = f'{protocol}://{domain}/'
                        try:
                            result = requests.get(url, timeout=10)
                        except requests.exceptions.RequestException as e:
                            log.debug(f"Exception {e} on {url}, ip={ip}")
                        else:
                            el = {'url': url, 'domain': domain, 'ip': ip}
                            if protocol == 'https':
                                output_secure.append(el)
                                domain = {'domain': domain}
                                if not domain in tls_domains:
                                    tls_domains.append(domain)
                            else:
                                output_insecure.append(el)
                            log.info(f"Found webserver {url} on {ip}")
        self.results['Insecure-Origins'] = output_insecure
        self.results['Secure-Origins'] = output_secure
        self.results['TLS-Domains'] = tls_domains


if __name__ == "__main__":
    Webservers.selftest()
