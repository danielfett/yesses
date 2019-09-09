import requests
import logging
from yesses.utils import force_ip_connection
import re
from yesses.types import IP, URL, Errors, Error, YType

log = logging.getLogger('scan/websecuritysettings')

class WebErrorsIPURL(IP, URL, Errors, YType):
    pass

class WebErrorIPURL(IP, URL, Errors, YType):
    pass


class WebSecuritySettings:
    DISALLOWED_METHODS = [
        'TRACE', 'TRACK', 'CONNECT'
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
            'header': 'Strict-Transport-Security',
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
            self.run_checks(*origin)
        
        #self.compress_results()
        return self.results

    def run_checks(self, url, domain, ip):
        log.info(f"Now checking {domain} on IP {ip}")
        with force_ip_connection(domain, ip):
            try:
                log.debug(f'GET {url} with IP {ip}')
                response = requests.get(url, timeout=10, stream=True)
            except requests.exceptions.RequestException as e:
                log.debug(f"Exception {e} on {url}, ip={ip}")
            else:
                if url.startswith('http://'):
                    self.check_http_settings(ip, response)
                self.check_https_settings(ip, response)

            response.close()

            found_disallowed_methods = []
            for method in self.disallowed_methods:
                try:
                    log.debug(f'{method} {url} with IP {ip}')
                    response = requests.request(method, url, timeout=10)
                except requests.exceptions.RequestException as e:
                    log.debug(f"Exception {e} on {url}, ip={ip}")
                else:
                    if response.status_code < 400:
                        found_disallowed_methods.append(f"must not support method {method}")
                        
            if found_disallowed_methods:
                self.results['Disallowed-Method-URLs'].append(WebErrorsIPURL(
                    url=url,
                    ip=ip,
                    errors=found_disallowed_methods
                ))


    def check_http_settings(self, ip, response):
        if len(response.history) == 0:
            self.results['Missing-HTTPS-Redirect-URLs'].append(WebErrorIPURL(
                url=response.url,
                ip=ip,
                error="no redirection encountered"
            ))

    def check_https_settings(self, ip, response):
        chain = [sr.url for sr in response.history + [response]]
        for step_uri in chain[1:]:
            if not step_uri.startswith('https://'):
                error = f"got redirections to non-HTTPS-URIs; redirection chain: {' → '.join(chain)}"
                self.results['Redirect-to-non-HTTPS-URLs'].append(WebErrorIPURL(
                    url=chain[0],
                    ip=ip,
                    error=error))
                break

        self.check_headers(ip, response)

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
                match = re.search('max-age=([0-9]+)', value, re.IGNORECASE)
                if match:
                    max_age = int(match.group(1))
                else:
                    max_age = 0
                return eval(rule['value_expr'])
            else:
                return True
            
        return None
        
    def check_headers(self, ip, response):
        try:
            actual_ip = response.raw._connection.sock.socket.getsockname()[0]
        except AttributeError:
            actual_ip = response.raw._connection.sock.getsockname()[0]
            
        self.check_disallowed_headers(actual_ip, response)
        self.check_missing_headers(actual_ip, response)
        self.check_insecure_cookies(actual_ip, response)

    def check_disallowed_headers(self, actual_ip, response):
        found_disallowed_headers = []
        for rule in self.disallowed_headers:
            for header, value in response.headers.items():
                match = self.match_header(response.url, rule, header, value)
                if match is True:
                    found_disallowed_headers.append(f"illegal header {header} (with value {value}): {rule['reason']}")
                    
        if found_disallowed_headers:
            self.results['Disallowed-Header-URLs'].append(WebErrorsIPURL(
                url=response.url,
                ip=actual_ip,
                errors=found_disallowed_headers
            ))

    def check_missing_headers(self, actual_ip, response):
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
                if 'value' in rule:
                    text = f" with value '{rule['value']}'"
                elif 'value_expr' in rule:
                    text = f" matching expression '{rule['value_expr']}'"
                else:
                    text = ''
                found_missing_headers.append(f"missing header: '{rule['header']}' {text}")
                
        if found_missing_headers:
            self.results['Missing-Header-URLs'].append(WebErrorsIPURL(
                url=response.url,
                ip=actual_ip,
                errors=found_missing_headers
            ))

    def check_insecure_cookies(self, actual_ip, response):
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
                found_insecure_cookies.append(f"insecure cookie {c.name}: {', '.join(insecure)}")
                
        if found_insecure_cookies:
            self.results['Insecure-Cookie-URLs'].append(WebErrorsIPURL(
                url=response.url,
                ip=actual_ip,
                errors=found_insecure_cookies
            ))
                
        

