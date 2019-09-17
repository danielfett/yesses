import logging
import dns.resolver
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA
from yesses.module import YModule, YExample

log = logging.getLogger('discover/domains_and_ips')

class DomainsAndIPs(YModule):
    """Based on domain names as "seeds", tries to find new domain names by
guessing expansions for wildcards and expanding CNAMEs. Finds IP
addresses from A and AAAA records.

This example expands domains from a list of domain seeds and the TLS names found with `discover TLS Certificates`. The alerting assumes that a whitelist of IP addresses (`Good-IPs`) exists.
```
  - discover Domains and IPs:
      seeds: use Domain-Seeds and TLS-Names
      resolvers: use DNS-Resolvers
    find:
      - IPs
      - Domains
      - DNS-Entries
    expect:
      - no added IPs, otherwise alert high
      - no added Domains, otherwise alert high
      - no added DNS-Entries, otherwise alert high
      - all IPs in Good-IPs, otherwise alert high
```

In this example, the same module is used to check if homoglyph (or homograph) domains (similar-looking domain names) have been registered. This example assumes that a list of such domains has been generated before.

```
data:
  Homoglyph-Domains:
    - eхample.com  # note that "х" is a greek character, not the latin "x"
    - 3xample.com
      (...)

run:
    (...)
  - discover Domains and IPs:
      seeds: use Homoglyph-Domains
      resolvers: use DNS-Resolvers
    find:
      - Domains as Homoglyph-Matches
    expect:
      - no Homoglyph-Matches, otherwise alert high
```

    """
    
    INPUTS = {
        "seeds": {
            "required_keys": [
                "domain"
            ],
            "description": "List of initial domains to start search from",
            "unwrap": True,
        },
        "resolvers": {
            "required_keys": [
                "ip"
            ],
            "description": "List of DNS resolvers to use. Default (empty list): System DNS resolvers.",
            "unwrap": True,
            "default": [],
        }
    }

    OUTPUTS = {
        "Domains": {
            "provided_keys": [
                "domain"
            ],
            "description": "List of domains found"
        },
        "IPs": {
            "provided_keys": [
                "ip"
            ],
            "description": "List of IPs found"
        },
        "DNS-Entries": {
            "provided_keys": [
                "domain",
                "ip"
            ],
            "description": "Pairs of (domain, IP) associations"
        },
        "Ignored-Domains": {
            "provided_keys": [
                "domain"
            ],
            "description": "CNAME targets that are not a subdomain of one of the seeding domains; these are not expanded further and are not contained in the other results."
        }
    }
    
    EXAMPLES = [
        YExample("discover DNS details of example.com", """
  - discover Domains and IPs:
      seeds:
        - domain: example.com
      resolvers: 
        - ip: '1.1.1.1'
    find:
      - IPs
      - Domains
      - DNS-Entries
""")
    ]
    
    
    rdtypes = [1, 28] # A and AAAA

    def run(self):
        self.resolver = dns.resolver.Resolver()
        if self.resolvers != []:
            self.resolver.nameservers = self.resolvers

        self.domains = set(self.seeds)
        self.ignored_domains = set()
        log.info(f'Domains before expanding: {self.domains}')
        self.expand_from_cnames()
        log.info(f'Found {len(self.domains)} domains after expanding CNAMEs')
        self.expand_wildcards()
        log.info(f'Found {len(self.domains)} domains after expanding wildcards')
        self.ips_from_domains()
        log.info(f'Left with {len(self.domains)} domains after checking for records')

        
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
        self.results['Ignored-Domains'] = [{'domain': d} for d in self.ignored_domains]

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
                        domains_to_ips.append({'domain': d, 'ip': answer.address})
                        ips.append(answer.address)
                    newdomainset.add(d)

        self.results['Domains'] = [{'domain': d} for d in newdomainset]
        self.results['DNS-Entries'] = domains_to_ips
        self.results['IPs'] = [{'ip': i} for i in set(ips)]
        

if __name__ == "__main__":
    DomainsAndIPs.selftest()
