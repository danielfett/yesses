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

Note that since this modules combines arbitrary IPs with a list of
domains, many non-existing or wrongly configured virtual servers may
be encountered. This can cause a high number of errors, in particular
TLS errors where the wrong certificate is encountered. These errors
are not necessarily a sign of a problem.

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
        "TLS-Error-Domains": {
            "provided_keys": [
                "domain",
                "url",
                "ip",
                "error",
            ],
            "description": "List of domains where an error during the TLS connection was encountered (e.g., wrong certificate)"
        },
        "Other-Error-Domains": {
            "provided_keys": [
                "domain",
                "url",
                "ip",
                "error",
            ],
            "description": "List of domains where any other error occured"
        },
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
""")
    ]

    def run(self):
        output_insecure = []
        output_secure = []
        other_error_domains = []
        tls_error_domains = []
        for ip in self.ips:
            for domain in self.domains:
                for protocol in ('http', 'https'):
                    with force_ip_connection(domain, ip):
                        url = f'{protocol}://{domain}/'
                        el = {'url': url, 'domain': domain, 'ip': ip}
                        
                        try:
                            result = requests.get(url, timeout=10)
                        except requests.exceptions.SSLError as e:
                            el['error'] = str(e)
                            tls_error_domains.append(el)
                        except requests.exceptions.RequestException as e:
                            el['error'] = str(e)
                            other_error_domains.append(el)
                        else:
                            if protocol == 'https':
                                output_secure.append(el)
                            else:
                                output_insecure.append(el)
                            log.info(f"Found webserver {url} on {ip}")
        self.results['Insecure-Origins'] = output_insecure
        self.results['Secure-Origins'] = output_secure
        self.results['TLS-Error-Domains'] = tls_error_domains
        self.results['Other-Error-Domains'] = other_error_domains


if __name__ == "__main__":
    Webservers.selftest()
