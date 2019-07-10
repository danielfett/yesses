import nmap
import logging
from bogosec.utils import force_ip_connection
import requests

log = logging.getLogger('scan/webservers')



class Webservers:
    def __init__(self, domains, ips):
        self.ips = ips
        self.domains = domains

    def run(self):
        output = []
        for ip in self.ips:
            for domain in self.domains:
                for protocol in ('http', 'https'):
                    with force_ip_connection(ip):
                        url = f'{protocol}://{domain}/'
                        try:
                            result = requests.get(url, timeout=10)
                        except requests.exceptions.RequestException as e:
                            log.debug(f"Exception {e} on {url}, ip={ip}")
                        else:
                            output.append((url, ip))
                            log.info(f"Found webserver {url} on {ip}")
        return {'Web-Origins': output}
