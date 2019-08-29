import requests
import logging
from bogosec.utils import force_ip_connection
import re

log = logging.getLogger('scan/websecuritysettings')

class WebSecuritySettings:
    DISALLOWED_METHODS = [
        'TRACE', 'TRACK', 'DELETE', 'PUT', 'CONNECT'
    ]
    
    DISALLOWED_HEADERS = [
        {
            'header': 'Access-Control-.*',
            'reason': 'CORS must be disabled',
        },
        {
            'header': 'Server',
            'value': '.* .*[0-9].*',
            'reason': 'Server headers must not contain version information',
        }
    ]

    REQUIRED_HEADERS = [
        {
            'header': 'Strict-Transport-Security:',
            'value_expr': 'max_age >= 31536000',
            'reason': 'STS header must be set and be valid for at least one year',
            'origin': 'https:',
        },
        {
            'header': 'X-Frame-Options',
            'value': 'DENY',
            'origin': 'https:',            
        },
        {
            'header': 'X-Content-Type-Options',
            'value': 'nosniff',
            'origin': 'https:',
        },
        {
            'header': 'Referrer-Policy',
            'origin': 'https:',
        },
        {
            'header': 'Content-Security-Policy',
            'origin': 'https:',
        },
        {
            'header': 'Expect-CT',
            'value_expr': 'value.startswith("enforce,") and max_age > 86400',
            'origin': 'https:',
        }
    ]
        
    
    def __init__(self,
                 origins,
                 disallowed_methods=DISALLOWED_METHODS,
                 disallowed_headers=DISALLOWED_HEADERS,
                 required_headers=REQUIRED_HEADERS,
    ):
        self.origins = origins
        self.results = {
            'Non-TLS-URLs': [],
            'Missing-HTTPS-Redirect-URLs': [],
            'Redirect-to-non-HTTPS-URLs': [],
            'Disallowed-Header-URLs': [],
            'Missing-Header-URLs': [],
            'Disallowed-Method-URLs': [],
            'Insecure-Cookie-URLs': [],
        }
        self.disallowed_headers = disallowed_headers
        self.disallowed_methods = disallowed_methods
        self.required_headers = required_headers

    def run(self):
        for origin in set(self.origins):
            url, domain, ip = origin
            log.info(f"GET {domain} on IP {ip}")
            with force_ip_connection(ip):
                try:
                    response = requests.get(url, timeout=10)
                except requests.exceptions.RequestException as e:
                    log.debug(f"Exception {e} on {url}, ip={ip}")
                else:
                    if url.startswith('http://'):
                        self.check_http_settings(url, ip, response)
                    self.check_https_settings(url, ip, response)

                found_disallowed_methods = []
                for method in self.disallowed_methods:
                    try:
                        response = requests.request(method, url, timeout=10)
                    except requests.exceptions.RequestException as e:
                        log.debug(f"Exception {e} on {url}, ip={ip}")
                    else:
                        if response.status_code < 400:
                            found_disallowed_methods.append(method)
                if found_disallowed_methods:
                    self.results['Disallowed-Method-URLs'].append((url, ip, found_disallowed_methods))
                    
        return self.results

    def check_http_settings(self, url, ip, response):
        if len(response.history) == 0:
            self.results['Missing-HTTPS-Redirect-URLs'].append((url, ip))

    def check_https_settings(self, url, ip, response):
        for step_response in response.history:
            if not step_response.url.startswith('https://'):
                self.results['Redirect-to-non-HTTPS-URLs'].append((url, ip))
                self.results['Non-TLS-URLs'].append((step_response.url, ip))

        if not response.url.startswith('https://'):
            self.results['Redirect-to-non-HTTPS-URLs'].append((url, ip))            
            self.results['Non-TLS-URLs'].append((response.url, ip))

        self.check_headers(response, ip)

    def match_header(self, url, rule, header, value):
        header = header.strip()
        value = value.strip()
        if re.fullmatch(rule['header'], header, re.IGNORECASE):
            if 'value' in rule:
                if re.fullmatch(rule['value'], value, re.IGNORECASE):
                    return True
                else:
                    return False
            elif 'value_expr' in rule:
                # check if max_age attribute is set
                match = re.search('max_age=([0-9]+)', value, re.IGNORECASE)
                if match:
                    max_age = int(match.group(1))
                else:
                    max_age = 0
                return eval(rule['value_expr'])
            else:
                return True
            
        return None
        
    def check_headers(self, response, ip):
        found_disallowed_headers = []
        for rule in self.disallowed_headers:
            for header, value in response.headers.items():
                match = self.match_header(response.url, rule, header, value)
                if match is True:
                    found_disallowed_headers.append((header, value))
        if found_disallowed_headers:
            self.results['Disallowed-Header-URLs'].append((response.url, ip, found_disallowed_headers))

        found_missing_headers = []
        for rule in self.required_headers:
            if 'origin' in rule:
                if not re.match(rule['origin'], response.url):
                    continue
                
            for header, value in response.headers.items():
                match = self.match_header(response.url, rule, header, value)
                if match is True:
                    break
            else:
                found_missing_headers.append((rule))
                
        if found_missing_headers:
            self.results['Missing-Header-URLs'].append((response.url, ip, found_missing_headers))

        # check cookie headers
        found_insecure_cookies = []
        for c in response.cookies:
            insecure = []
            if response.url.startswith('https:'):
                if not c.name.startswith('__Secure-') and not c.name.startswith('__Host-'):
                    insecure.append('missing __Secure- or __Host-Prefix')
                if not c.secure:
                    insecure.append('missing secure attribute')
                if not c.has_nonstandard_attr('SameSite'):
                    insecure.append('missing SameSite attribute')
                    
            if not c.has_nonstandard_attr('HttpOnly'):
                insecure.append('missing HttpOnly attribute')

            if len(insecure):
                found_insecure_cookies.append((c.name, ', '.join(insecure)))
                
        if found_insecure_cookies:
            self.results['Insecure-Cookie-URLs'].append((response.url, ip, found_insecure_cookies))
                
        

