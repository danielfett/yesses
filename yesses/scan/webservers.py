import nmap
import logging
from yesses.utils import force_ip_connection
import requests

log = logging.getLogger('scan/webservers')



class Webservers:
    def __init__(self, domains, ips):
        self.ips = ips
        self.domains = domains

    def run(self):
        output = []
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
                            output.append((url, domain, ip))
                            if protocol == 'https':
                                output_secure.append((url, domain, ip))
                                tls_domains.append(domain)
                            log.info(f"Found webserver {url} on {ip}")
        return {
            'Web-Origins': output,
            'TLS-Web-Origins': output_secure,
            'TLS-Domains': tls_domains,
        }
