from tlsprofiler import TLSProfiler
from yesses.module import YModule
import requests
import logging

log = logging.getLogger('scan/tlssettings')


class TLSSettings(YModule):
    """Uses the sslyze library to scan a webserver's TLS configuration and
compare it to the Mozilla TLS configuration profiles.

    """
    INPUTS = {
        "domains": {
            "required_keys": [
                "domain"
            ],
            "description": "List of domain names to scan.",
            "unwrap": True,
        },
        "tls_profile": {
            "required_keys": None,
            "description": "The Mozilla TLS profile to test against (`old`, `intermediate`, or `new`).",
            "default": "intermediate",
        }
    }

    OUTPUTS = {
        "TLS-Profile-Mismatch-Domains": {
            "provided_keys": [
                "domain",
                "errors"
            ],
            "description": "Domains of servers that do not match the TLS profile. `errors` contains the list of deviations from the profile."
        },
        "TLS-Validation-Fail-Domains": {
            "provided_keys": [
                "domain",
                "errors"
            ],
            "description": "Domains of servers that presented an invalid certificate. `errors` contains the list of validation errors."
        },
        "TLS-Vulnerability-Domains": {
            "provided_keys": [
                "domain",
                "errors"
            ],
            "description": "Domains where a TLS vulnerability was detected. `errors` contains the list of vulnerabilities found."
        },
        "TLS-Okay-Domains": {
            "provided_keys": [
                "domain"
            ],
            "description": "Domains where no errors or vulnerabilities were found."
        },
        "TLS-Other-Error-Domains": {
            "provided_keys": [
                "domain",
                "error"
            ],
            "description": "Domains that could not be tested because of some error (e.g., a network error). `error` contains the error description."
        }
    }

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
            self.results['TLS-Validation-Fail-Domains'].append({
                'domain': domain,
                'errors': tls_results.validation_errors,
            })
            
        if not tls_results.profile_matched:
            self.results['TLS-Profile-Mismatch-Domains'].append({
                'domain': domain,
                'errors': tls_results.profile_errors,
            })

        if tls_results.vulnerable:
            self.results['TLS-Vulnerability-Domains'].append({
                'domain': domain,
                'errors': tls_results.vulnerability_errors,
            })
