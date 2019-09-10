import nmap
import logging
from yesses.utils import force_ip_connection
import requests
from yesses.module import YModule, unwrap_key

log = logging.getLogger('scan/webservers')



class Webservers(YModule):
    """
    Scans an IP range for web servers (on standard HTTP and HTTPs ports);
    combines a list of IPs with a list of domains to use for the Host
    header in web requests.
    """
    
    INPUTS = [
        ('ips', ['ip'], 'IP range to scan (e.g., `use HTTP-IPs and HTTPS-IPs`)'),
        ('domains', ['domain'], 'Domain names to try on these IPs'),
    ]

    OUTPUTS = [
        ('Web-Origins', ['domain', 'url', 'ip' ], 'HTTP origins'),
        ('TLS-Web-Origins', ['domain', 'url', 'ip' ], 'as above, but for HTTPS'),
        ('TLS-Domains', ['domain'], 'List of domains with HTTPS servers'),
    ]
    
    @unwrap_key('domains', 'domain')
    @unwrap_key('ips', 'ip')
    def __init__(self, step, domains, ips):
        self.step = step
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
                            el = {'url': url, 'domain': domain, 'ip': ip}
                            output.append(el)
                            if protocol == 'https':
                                output_secure.append(el)
                                tls_domains.append({'domain': domain})
                            log.info(f"Found webserver {url} on {ip}")
        self.results['Web-Origins'] = output
        self.results['TLS-Web-Origins'] = output_secure
        self.results['TLS-Domains'] = tls_domains
