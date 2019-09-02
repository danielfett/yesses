import requests
import json
import logging

log = logging.getLogger('discover/tls_certificates')

class TLSCertificates:
    base_url = "https://crt.sh/?q=%25.{}&output=json"
    cert_url = "https://crt.sh/?id={min_cert_id}"
    user_agent = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1'
    
    def __init__(self, seeds):
        self.seeds = seeds
        log.info(f'Using seeds: {seeds!r}')

    def run(self):
        domains = set()
        certs = set()
        
        for d in self.seeds:
            found_domains, found_certs = self.from_ctlog(d)
            domains |= found_domains
            certs |= found_certs

        return {
            'TLS-Names': domains,
            'TLS-Certificates': certs,
        }

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
