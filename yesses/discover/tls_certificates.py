import requests
import json
import logging
from yesses.module import YModule, YExample
from time import sleep

log = logging.getLogger("discover/tls_certificates")


class TLSCertificates(YModule):
    """Queries Certificate Transparency logs (using
https://sslmate.com/certspotter) for existing TLS certificates for
given domains and their subdomains.

Note: The output may contain wildcards, e.g., '*.example.com'.

    """

    INPUTS = {
        "seeds": {
            "required_keys": ["domain"],
            "description": "List of domains for search. Certificates for domains in this list and their subdomains will be found",
            "unwrap": True,
        }
    }

    OUTPUTS = {
        "TLS-Names": {
            "provided_keys": ["domain"],
            "description": "DNS names found in certificates (may include wildcards, such as `*.example.com`).",
        },
        "TLS-Certificates": {
            "provided_keys": ["pubkey"],
            "description": "The hex-encoded SHA-256 fingerprint of the certificate's public key.",
        },
    }

    EXAMPLES = [
        YExample(
            "list certificates of example.com",
            """
  - discover TLS Certificates:
      seeds:
        - domain: example.com
    find:
      - TLS-Names
      - TLS-Certificates
    """,
        )
    ]

    base_url = "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names"
    user_agent = (
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1"
    )

    TRIES = 20
    WAIT = 10

    def run(self):
        domains = set()
        certs = set()

        for d in self.seeds:
            found_domains, found_certs = self.from_ctlog(d)
            domains |= found_domains
            certs |= found_certs

        self.results["TLS-Names"] = [{"domain": d} for d in domains]
        self.results["TLS-Certificates"] = [{"pubkey": c} for c in certs]

    def from_ctlog(self, query_domain):
        start_url = self.base_url.format(query_domain)
        url = start_url

        data = []

        tries = self.TRIES
        while tries:
            req = requests.get(url, headers={"User-Agent": self.user_agent})
            if req.ok:
                content = req.json()
                if len(content) == 0:
                    break
                else:
                    data += content
                    url = (
                        start_url + f"&after={content[-1]['id']}"
                    )  # pagination: go to next page
            else:
                log.info(
                    f"Error retrieving {url}, trying again in {self.WAIT} seconds."
                )
                tries -= 1
                sleep(self.WAIT)
        else:
            raise Exception(f"Cannot retrieve certificate transparency log from {url}")

        found_domains = set(name for crt in data for name in crt["dns_names"])
        found_certs = set(crt["pubkey_sha256"] for crt in data)
        return found_domains, found_certs


if __name__ == "__main__":
    TLSCertificates.selftest()
