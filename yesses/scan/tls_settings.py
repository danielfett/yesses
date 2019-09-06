from ssllabs import SSLLabsAssessment
import logging
import re

log = logging.getLogger('scan/tls_settings')

class TLSSettings:
    def __init__(self, domains=None, allowed_grades=['A', 'A+'], skip=None):
        self.hosts = domains
        self.allowed_grades = allowed_grades
        self.skip = skip

    def run(self):
        results = {
            'TLS-Grade-Success-IPs':[],
            'TLS-Grade-Fail-IPs':[],
            'TLS-Grade-Error-IPs':[],
            'TLS-Grade-Success':[],
            'TLS-Grade-Fail':[],
            'TLS-Grade-Error':[],
        }
        for host in self.hosts:
            if self.skip is not None and re.match(self.skip, host):
                continue
            log.info(f'Starting Qualys TLS scan for {host}')
            
            assessment = SSLLabsAssessment(host=host)
            
            info = assessment.analyze(
                ignore_mismatch='off',
                from_cache='on',
                max_age='12',
                return_all='done',
                publish='off'
            )
            for endpoint in info['endpoints']:
                ip = endpoint['ipAddress']
                ip_and_host = {'IP': ip, 'Host': host, 'Grade': endpoint['grade']}
                if endpoint['statusMessage'] != 'Ready':
                    results['TLS-Grade-Error'].append(ip_and_host)
                    results['TLS-Grade-Error-IPs'].append(ip)
                elif endpoint['grade'] in self.allowed_grades:
                    results['TLS-Grade-Success'].append(ip_and_host)
                    results['TLS-Grade-Success-IPs'].append(ip)
                else:
                    results['TLS-Grade-Fail'].append(ip_and_host)
                    results['TLS-Grade-Fail-IPs'].append(ip)
        return results
            
