import requests
import json
import logging
from yesses.module import unwrap_key, YModule

log = logging.getLogger('discover/tls_certificates')

class TLSCertificates(YModule):
    """Queries Certificate Transparency logs (using https://crt.sh) for
existing TLS certificates for given domains and their subdomains.

    """
    
    INPUTS = [
        ('seeds', ['domain'], 'List of domains for search. Certificates for domains in this list and their subdomains will be found'),
    ]

    OUTPUTS = [
        ('TLS-Names', ['domain'], 'DNS names found in certificates (may include wildcards, such as `*.example.com`).'),
        ('TLS-Certificates', ['certificate_id', 'certificate_url'], 'Unique identifiers for found TLS certificates; also links to more information about the certificates. `certificate_id` and `certificate_url` have the same content in this module, as the URI is also used to uniquely identify the certificate.'),
    ]
    
    base_url = "https://crt.sh/?q=%25.{}&output=json"
    cert_url = "https://crt.sh/?id={min_cert_id}"
    user_agent = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1'

    @unwrap_key('seeds', 'domain')
    def __init__(self, step, seeds):
        self.step = step
        self.seeds = seeds
        log.info(f'Using seeds: {seeds!r}')

    def run(self):
        domains = set()
        certs = set()
        
        for d in self.seeds:
            found_domains, found_certs = self.from_ctlog(d)
            domains |= found_domains
            certs |= found_certs

        self.results['TLS-Names'] = [{'domain': d} for d in domains]
        self.results['TLS-Certificates'] = [{'certificate_id': c, 'certificate_url': c} for c in certs]

    def from_ctlog(self, query_domain):
        url = self.base_url.format(query_domain)
        req = requests.get(url, headers={'User-Agent': self.user_agent})

        if not req.ok:
            raise Exception(f"Cannot retrieve certificate transparency log from {url}")
        content = req.content.decode('utf-8')
        data = json.loads(content)

        found_domains = set(crt['name_value'] for crt in data)
        found_certs = set(self.cert_url.format(**crt) for crt in data)
        return found_domains, found_certs
