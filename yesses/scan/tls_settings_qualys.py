from ssllabs import SSLLabsAssessment
import logging
import re
from yesses.module import unwrap_key, YModule

log = logging.getLogger('scan/tls_settings')

class TLSSettingsQualys(YModule):
    """Uses the Qualys SSL Labs TLS assessment service to determine the
security level of the TLS configuration. Only works for the HTTPS
standard port 443, therefore expects a list of domain names, not web
origins.

Note: The assessment service is provided free of charge by Qualys SSL
Labs, subject to their terms and conditions:
https://dev.ssllabs.com/about/terms.html
    """

    INPUTS = [
        ('domains', ['domain'], 'List of domain names to scan.'),
        ('allowed_grades', None, 'List of grades that are deemed acceptable. See https://ssllabs.com for details. (Default: `A` and `A+`.'),
    ]

    OUTPUTS = [
        ('TLS-Grade-Success', ['ip', 'domain', 'grade'], 'Object containing information about IP/Host combinations that passed the SSL test with an acceptable grade.'),
        ('TLS-Grade-Fail', ['ip', 'domain', 'grade'], 'As above, but only IP/Host combinations that did not get an acceptable grade.'),
        ('TLS-Grade-Error', ['ip', 'domain', 'grade'], 'As above, but only IP/Host combinations that failed due to errors during the test.'),
    ]
    
    @unwrap_key('domains', 'domain')
    def __init__(self, step, domains=None, allowed_grades=['A', 'A+']):
        self.step = step
        self.hosts = domains
        self.allowed_grades = allowed_grades

    def run(self):
        for host in self.hosts:
            self.run_assessment(host)

    def run_assessment(self, host):
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
            ip_and_host = {'ip': ip, 'domain': host, 'grade': endpoint['grade']}
            if endpoint['statusMessage'] != 'Ready':
                self.results['TLS-Grade-Error'].append(ip_and_host)
            elif endpoint['grade'] in self.allowed_grades:
                self.results['TLS-Grade-Success'].append(ip_and_host)
            else:
                self.results['TLS-Grade-Fail'].append(ip_and_host)

            
