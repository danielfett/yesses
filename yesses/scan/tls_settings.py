from tlsprofiler import TLSProfiler
import requests
import logging

from yesses.types import Domain, Error, Errors, YType

log = logging.getLogger('scan/tlssettings')

class TLSErrorDomain(Domain, Error, YType):
    pass

class TLSOkayDomain(Domain, YType):
    pass

class TLSSettings:
    def __init__(self, domains=None, tls_profile='intermediate'):
        self.domains = domains
        self.tls_profile = tls_profile

    def run(self):
        self.results = {
            'TLS-Profile-Mismatch-Errors-Domains': [],
            'TLS-Validation-Errors-Domains': [],
            'TLS-Vulnerability-Errors-Domains': [],
            'TLS-Okay-Domains': [],
            'TLS-Other-Error-Domains': [],
        }

        for domain in self.domains:
            self.scan_domain(domain)

        return self.results

    def scan_domain(self, domain):
        scanner = TLSProfiler(domain, self.tls_profile)
        if scanner.server_error is not None:
            self.results['TLS-Other-Error-Domains'].append(
                TLSErrorDomain(
                    domain=domain,
                    error=scanner.server_error
            ))
            return
        tls_results = scanner.run()
        if tls_results.all_ok:
            self.results['TLS-Okay-Domains'].append(TLSOkayDomain(domain=domain))
            
        if not tls_results.validated:
            self.results['TLS-Validation-Errors-Domains'].append(TLSErrorDomain(
                domain=domain,
                errors=tls_results.validation_errors,
            ))
            
        if not tls_results.profile_matched:
            self.results['TLS-Profile-Mismatch-Errors-Domains'].append(TLSErrorDomain(
                domain=domain,
                errors=tls_results.profile_errors,
            ))

        if tls_results.vulnerable:
            self.results['TLS-Vulnerability-Errors-Domains'].append(TLSErrorDomain(
                domain=domain,
                errors=tls_results.vulnerability_errors,
            ))
