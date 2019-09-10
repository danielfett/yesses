from tlsprofiler import TLSProfiler
from yesses.module import unwrap_key, YModule
import requests
import logging

log = logging.getLogger('scan/tlssettings')


class TLSSettings(YModule):
    """Uses the sslyze library to scan a webserver's TLS configuration and
compare it to the Mozilla TLS configuration profiles.

    """

    INPUTS = [
        ('domains', ['domain'], 'List of domain names to scan.'),
        ('tls_profile', None, 'The Mozilla TLS profile to test against (`old`, `intermediate`, or `new`).')
    ]

    OUTPUTS = [
        ('TLS-Profile-Mismatch-Domains', ['domain', 'errors'], 'Domains of servers that do not match the TLS profile. `errors` contains the list of deviations from the profile.'),
        ('TLS-Validation-Fail-Domains', ['domain', 'errors'], 'Domains of servers that presented an invalid certificate. `errors` contains the list of validation errors.'),
        ('TLS-Vulnerability-Domains', ['domain', 'errors'], 'Domains where a TLS vulnerability was detected. `errors` contains the list of vulnerabilities found.'),
        ('TLS-Okay-Domains', ['domain'], 'Domains where no errors or vulnerabilities were found.'),
        ('TLS-Other-Error-Domains', ['domain', 'error'], 'Domains that could not be tested because of some error (e.g., a network error). `error` contains the error description.'),
    ]
    
    @unwrap_key('domains', 'domain')
    def __init__(self, step, domains=None, tls_profile='intermediate'):
        self.step = step
        self.domains = domains
        self.tls_profile = tls_profile

    def run(self):
        for domain in self.domains:
            self.scan_domain(domain)

    def scan_domain(self, domain):
        scanner = TLSProfiler(domain, self.tls_profile)
        if scanner.server_error is not None:
            self.results['TLS-Other-Error-Domains'].append({
                    'domain': domain,
                    'error': scanner.server_error,
                })
            return
        tls_results = scanner.run()
        if tls_results.all_ok:
            self.results['TLS-Okay-Domains'].append({
                'domain': domain
            })
            
        if not tls_results.validated:
            self.results['TLS-Validation-Errors-Domains'].append({
                'domain': domain,
                'errors': tls_results.validation_errors,
            })
            
        if not tls_results.profile_matched:
            self.results['TLS-Profile-Mismatch-Errors-Domains'].append({
                'domain': domain,
                'errors': tls_results.profile_errors,
            })

        if tls_results.vulnerable:
            self.results['TLS-Vulnerability-Errors-Domains'].append({
                'domain': domain,
                'errors': tls_results.vulnerability_errors,
            })
