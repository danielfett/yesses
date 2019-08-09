import requests
import logging
from bogosec.utils import force_ip_connection

log = logging.getLogger('scan/websecuritysettings')

class WebSecuritySettings:
    def __init__(self, origins):
        self.origins = origins
        self.results = {
            'Non-TLS-URLs': [],
            'Missing-HTTPS-Redirect-URLs': [],
            'Redirect-to-non-HTTPS-URLs': [],
        }

    def run(self):
        for origin in self.origins:
            url, domain, ip = origin
            log.info(f"GET {domain}")
            with force_ip_connection(ip):
                try:
                    response = requests.get(url, timeout=10)
                except requests.exceptions.RequestException as e:
                    log.debug(f"Exception {e} on {url}, ip={ip}")
                else:
                    if url.startswith('http://'):
                        self.check_http_settings(url, response)
                    self.check_https_settings(url, response)
        return self.results

    def check_http_settings(self, url, response):
        if len(response.history) == 0:
            self.results['Missing-HTTPS-Redirect-URLs'].append(url)

    def check_https_settings(self, url, response):
        for step_response in response.history:
            if not step_response.url.startswith('https://'):
                self.results['Redirect-to-non-HTTPS-URLs'].append(url)
                self.results['Non-TLS-URLs'].append(step_response.url)

        if not response.url.startswith('https://'):
            self.results['Redirect-to-non-HTTPS-URLs'].append(url)            
            self.results['Non-TLS-URLs'].append(response.url)

        
            
            

            
        
