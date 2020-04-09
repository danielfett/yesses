import logging
from concurrent.futures import ThreadPoolExecutor

from dnssec_scanner import DNSSECScanner
from yesses.module import YModule, YExample

log = logging.getLogger("scan/dnssec_scanner")
logging.getLogger("dnssec_scanner").setLevel(logging.CRITICAL)


class Dnssec(YModule):
    """Use the DNSSEC Scanner Python package to check the DNSSEC configuration
    of domain names. The DNSSEC Scanner provides log, warning and error messages
    for the DNSSEC validation process.
    """

    INPUTS = {
        "domains": {
            "required_keys": ["domain"],
            "description": "List of domain names to scan their DNSSEC configuration.",
            "unwrap": True,
        },
        "parallel_requests": {
            "required_keys": None,
            "description": "Number of parallel DNSSEC scan commands to run.",
            "default": 10,
        },
    }

    OUTPUTS = {
        "DNSSEC-Logs-Domains": {
            "provided_keys": ["domain", "logs"],
            "description": "Log messages for the verification process of each domain.",
        },
        "DNSSEC-Warnings-Domains": {
            "provided_keys": ["domain", "warnings"],
            "description": "Warning messages for the verification process of each domain.",
        },
        "DNSSEC-Errors-Domains": {
            "provided_keys": ["domain", "errors"],
            "description": "Error messages for the verification process of each domain.",
        },
        "DNSSEC-Summary-Domains": {
            "provided_keys": ["domain", "status", "note"],
            "description": "DNSSEC status (0=SECURE&#124;1=INSECURE&#124;2=BOGUS) and a note for the found RR sets.",
        },
        "DNSSEC-Other-Error-Domains": {
            "provided_keys": ["domain", "error"],
            "description": "Domains that could not be scan because fo some error. `error` contains the error description.",
        },
    }

    EXAMPLES = [
        YExample(
            "Check DNSSEC configuration of dnssec-deployment.org",
            """
  - scan Dnssec:
    domains:
      - domain: dnssec-deployment.org
    find:
      - DNSSEC-Logs-Domains
      - DNSSEC-Warnings-Domains
      - DNSSEC-Errors-Domains
      - DNSSEC-Summary-Domains
      - DNSSEC-Other-Error-Domains
        """,
        )
    ]

    def run(self):
        with ThreadPoolExecutor(max_workers=self.parallel_requests) as executor:
            executor.map(self.scan_domain, self.domains)

    def scan_domain(self, domain: str):
        log.info(f"Scan domain {domain}")
        scanner = DNSSECScanner(domain)
        try:
            result = scanner.run_scan()
        except Exception as e:
            self.results["DNSSEC-Other-Error-Domains"].append(
                {"domain": domain, "error": str(e)}
            )
            return
        self.results["DNSSEC-Logs-Domains"].append(
            {"domain": domain, "logs": result.logs}
        )
        self.results["DNSSEC-Warnings-Domains"].append(
            {"domain": domain, "warnings": result.warnings}
        )
        self.results["DNSSEC-Errors-Domains"].append(
            {"domain": domain, "errors": result.errors}
        )
        self.results["DNSSEC-Summary-Domains"].append(
            {"domain": domain, "status": result.state.value, "note": result.note}
        )
