from tlsprofiler import TLSProfiler
from yesses.module import YModule, YExample
import requests
import logging
from concurrent.futures import ThreadPoolExecutor

log = logging.getLogger("scan/tlssettings")


class TLSSettings(YModule):
    """Uses the sslyze library to scan a webserver's TLS configuration and
compare it to the Mozilla TLS configuration profiles.

    """

    INPUTS = {
        "domains": {
            "required_keys": ["domain"],
            "description": "List of domain names to scan.",
            "unwrap": True,
        },
        "tls_profile": {
            "required_keys": None,
            "description": "The Mozilla TLS profile to test against (`old`, `intermediate`, or `modern`).",
            "default": "intermediate",
        },
        "ca_file": {
            "required_keys": None,
            "description": "Path to a trusted custom root certificates in PEM format.",
            "default": None,
        },
        "parallel_requests": {
            "required_keys": None,
            "description": "Number of parallel TLS scan commands to run.",
            "default": 10,
        },
    }

    OUTPUTS = {
        "TLS-Profile-Mismatch-Domains": {
            "provided_keys": ["domain", "errors"],
            "description": "Domains of servers that do not match the TLS profile. `errors` contains the list of deviations from the profile.",
        },
        "TLS-Validation-Fail-Domains": {
            "provided_keys": ["domain", "errors"],
            "description": "Domains of servers that presented an invalid certificate. `errors` contains the list of validation errors.",
        },
        "TLS-Certificate-Warnings-Domains": {
            "provided_keys": ["domain", "warnings"],
            "description": "Domains of servers that have not the recommended certificate values. `warnings` contains all differgences from the recommended values.",
        },
        "TLS-Vulnerability-Domains": {
            "provided_keys": ["domain", "errors"],
            "description": "Domains where a TLS vulnerability was detected. `errors` contains the list of vulnerabilities found.",
        },
        "TLS-Okay-Domains": {
            "provided_keys": ["domain"],
            "description": "Domains where no errors or vulnerabilities were found.",
        },
        "TLS-Other-Error-Domains": {
            "provided_keys": ["domain", "error"],
            "description": "Domains that could not be tested because of some error (e.g., a network error). `error` contains the error description.",
        },
    }

    EXAMPLES = [
        YExample(
            "Check TLS settings on badssl.com",
            """
 - scan TLS Settings:
     domains:
      - domain: mozilla-intermediate.badssl.com
     tls_profile: intermediate
   find:
     - TLS-Profile-Mismatch-Domains
     - TLS-Validation-Fail-Domains
     - TLS-Certificate-Warnings-Domains
     - TLS-Vulnerability-Domains
     - TLS-Okay-Domains
     - TLS-Other-Error-Domains
   expect:
     - some TLS-Okay-Domains, otherwise alert medium
""",
        )
    ]

    def run(self):
        with ThreadPoolExecutor(max_workers=self.parallel_requests) as executor:
            executor.map(self.scan_domain, self.domains)

    def scan_domain(self, domain):
        scanner = TLSProfiler(domain, self.tls_profile, ca_file=self.ca_file)
        if scanner.server_error is not None:
            self.results["TLS-Other-Error-Domains"].append(
                {"domain": domain, "error": scanner.server_error,}
            )
            return
        try:
            tls_results = scanner.run()
        except Exception as e:
            self.results["TLS-Other-Error-Domains"].append(
                {"domain": domain, "error": str(e),}
            )
            return

        if tls_results.all_ok:
            self.results["TLS-Okay-Domains"].append({"domain": domain})

        if not tls_results.validated:
            self.results["TLS-Validation-Fail-Domains"].append(
                {"domain": domain, "errors": tls_results.validation_errors}
            )

        if not tls_results.no_warnings:
            self.results["TLS-Certificate-Warnings-Domains"].append(
                {"domain": domain, "warnings": tls_results.cert_warnings}
            )

        if not tls_results.profile_matched:
            self.results["TLS-Profile-Mismatch-Domains"].append(
                {"domain": domain, "errors": tls_results.profile_errors,}
            )

        if tls_results.vulnerable:
            self.results["TLS-Vulnerability-Domains"].append(
                {"domain": domain, "errors": tls_results.vulnerability_errors,}
            )
