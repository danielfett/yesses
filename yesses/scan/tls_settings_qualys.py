from ssllabs import SSLLabsAssessment
import logging
import re
from yesses.module import YModule

log = logging.getLogger("scan/tls_settings")


class TLSSettingsQualys(YModule):
    """Uses the Qualys SSL Labs TLS assessment service to determine the
security level of the TLS configuration. Only works for the HTTPS
standard port 443, therefore expects a list of domain names, not web
origins.

Note: The assessment service is provided free of charge by Qualys SSL
Labs, subject to their terms and conditions:
https://dev.ssllabs.com/about/terms.html
    """

    INPUTS = {
        "domains": {
            "required_keys": ["domain"],
            "description": "List of domain names to scan.",
            "unwrap": True,
        },
        "allowed_grades": {
            "required_keys": None,
            "description": "List of grades that are deemed acceptable. See https://ssllabs.com for details.",
            "default": ["A", "A+"],
        },
    }

    OUTPUTS = {
        "TLS-Grade-Success": {
            "provided_keys": ["ip", "domain", "grade"],
            "description": "Object containing information about IP/Host combinations that passed the SSL test with an acceptable grade.",
        },
        "TLS-Grade-Fail": {
            "provided_keys": ["ip", "domain", "grade"],
            "description": "As above, but only IP/Host combinations that did not get an acceptable grade.",
        },
        "TLS-Grade-Error": {
            "provided_keys": ["ip", "domain", "grade"],
            "description": "As above, but only IP/Host combinations that failed due to errors during the test.",
        },
    }

    def run(self):
        for host in self.domains:
            self.run_assessment(host)

    def run_assessment(self, host):
        log.info(f"Starting Qualys TLS scan for {host}")

        assessment = SSLLabsAssessment(host=host)

        info = assessment.analyze(
            ignore_mismatch="off",
            from_cache="on",
            max_age="12",
            return_all="done",
            publish="off",
        )
        for endpoint in info["endpoints"]:
            ip_and_host = {"ip": ip, "domain": host, "grade": endpoint["grade"]}
            if endpoint["statusMessage"] != "Ready":
                self.results["TLS-Grade-Error"].append(ip_and_host)
            elif endpoint["grade"] in self.allowed_grades:
                self.results["TLS-Grade-Success"].append(ip_and_host)
            else:
                self.results["TLS-Grade-Fail"].append(ip_and_host)
