import requests
import json
import logging
import dns.resolver
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA

log = logging.getLogger('discover/domains_and_ips')

class DomainsAndIPs:
    base_url = "https://crt.sh/?q=%25.{}&output=json"
    user_agent = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1'
    rdtypes = [1, 28] # A and AAAA
    
    def __init__(self, seeds, resolvers=None):
        self.seeds = seeds
        log.info(f'Using seeds: {seeds!r}')
        self.resolver = dns.resolver.Resolver()
        if resolvers is not None:
            self.resolver.nameservers = resolvers

    def run(self):
        self.domains = set(self.seeds)
        self.ignored_domains = set()
        for d in self.seeds:
            self.domains |= self.domains_from_ctlog(d)
        log.info(f'Domains before expanding: {self.domains}')
        self.expand_from_cnames()
        log.info(f'Found {len(self.domains)} domains after expanding CNAMEs')
        self.expand_wildcards()
        log.info(f'Found {len(self.domains)} domains after expanding wildcards')
        self.ips_from_domains()
        log.info(f'Left with {len(self.domains)} domains after checking for records')
        
        return {
            'Domains': self.domains,
            'IPs': self.ips,
            'DNS-Entries': self.domains_to_ips,
            'Ignored-Domains': self.ignored_domains,
        }

    def domains_from_ctlog(self, query_domain):
        url = self.base_url.format(query_domain)
        req = requests.get(url, headers={'User-Agent': self.user_agent})

        if not req.ok:
            raise Exception(f"Cannot retrieve certificate transparency log from {url}")
        content = req.content.decode('utf-8')
        data = json.loads(content)
        return set(crt['name_value'] for crt in data)

    def expand_from_cnames(self):
        newdomains = set()
        
        for d in self.domains:
            if d.startswith('*'):
                continue
            try:
                answers = self.resolver.query(d, 'CNAME')
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                continue
            
            for rdata in answers:
                candidate = rdata.target.to_text()[:-1]
                for s in self.seeds:
                    if candidate.endswith(f'.{s}'):
                        newdomains.add(candidate)
                        break
                else:
                    self.ignored_domains |= set(candidate)
                        
        self.domains |= newdomains        

    def expand_wildcards(self):
        subdomains = set()
        for d in self.domains:
            if d.startswith('*'):
                continue
            for s in self.seeds:
                if d.endswith('.' + s):
                    subdomains.add(d[:-(len(s)+1)])
        log.info(f'Found subdomains: {subdomains!r}')

        newdomainset = set()
        for d in self.domains:
            if not d.startswith('*'):
                newdomainset.add(d)
            else:
                for subdomain in subdomains:
                    newdomain = f'{subdomain}{d[1:]}'
                    newdomainset.add(newdomain)
                    
        self.domains = newdomainset

    def ips_from_domains(self):
        newdomainset = set()
        ips = []
        domains_to_ips = []

        for d in self.domains:
            for rdtype in self.rdtypes:
                log.debug(f"Checking DNS: {rdtype} {d}")
                try:
                    answers = self.resolver.query(d, rdtype)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.NoAnswer) as e:
                    log.debug(f"Not found: {e}")
                else:
                    for answer in answers:
                        domains_to_ips.append((d, answer.address))
                        ips.append(answer.address)
                    newdomainset.add(d)

        self.domains = list(newdomainset)
        self.domains_to_ips = domains_to_ips
        self.ips = list(set(ips))
        

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    import sys
    d = DiscoverDomainsAndIPs(sys.argv[1:])
    print (d.run())
