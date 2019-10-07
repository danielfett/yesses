# yesses #

Simple tool to enumerate domains and IPs and test those domains and
IPs for basic network and web security properties.

yesses provides a number of modules that each perform a certain task.
For example, the module `discover Domains and IPs` queries DNS servers
for IP addresses. Each module has a number of defined inputs (in this
case, for example, domain names) and outputs (e.g., IP addresses and
domain names expanded from CNAMEs). These outputs are called "findings".

Modules can be combined by feeding the findings of one module into the
input of another module. For example, the module `discover Webservers`
can use the domain names and IP addresses from `discover Domains and
IPs` as inputs. This enables a dynamic scanning of infrastructures
without configuring every domain name, IP address, etc. manually.

After the execution of each module, alerts can be defined. Alerts can
trigger when certain elements are contained (or are not contained) in
the output of a module; alerts can also be triggered when — compared
to the previous run of yesses — new elements appear in the output of a
module. 

Alerts are processed by one or more user-defined outputs. yesses comes
with an HTML template output and Slack notification output.

## Table of Contents ##

  * [Usage](#user-content-usage)
    * [Concepts](#user-content-concepts)
    * [Configuration File](#user-content-configuration-file)
  * [Discovery and Scanning Modules](#user-content-discovery-and-scanning-modules)
  * [Output Modules](#user-content-output-modules)

# Usage #

```
usage: run.py [-h] [--verbose] [--resume] [--repeat N] [--fresh] [--test]
              [--generate-readme]
              [configfile]

Tool to scan for network and web security features

positional arguments:
  configfile         Config file in yaml format. Required unless --test or
                     --generate-readme are used.

optional arguments:
  -h, --help         show this help message and exit
  --verbose, -v      Increase debug level to show debug messages.
  --resume, -r       Resume scanning from existing resumefile.
  --repeat N         Repeat last N steps of run (for debugging). Will inhibit
                     warnings of duplicate output variables.
  --fresh, -f        Do not use existing state files. Usage of this required
                     when datastructures in this application changed.
  --test             Run a self-test. This executes the examples contained in
                     all modules.
  --generate-readme  Run a self-test (as above) and generate the file
                     README.md using the test results.

```

## Concepts ##

A **run** of yesses consists of a call to one or more **modules**. A
module, as described above, performs one or more checks. Each module
accepts a custom set of input values and output values. The details
for each module are described below.

There exists a global dictionary of facts, or **findings** which can
be used as input for other modules or to create alerts based on rules
on the findings. At the start of the run, the findings dictionary is
empty, but can be pre-filled with **static data** in the configuration
file, e.g., a list of domains to scan. When a module is called, **input
values** can be taken from the findings dictionary (using the `use`
keyword).

The module produces an **output dictionary** containing the module's own
findings. Selected keys from this output dictionary can be merged into
the global findings dictionary. (If necessary, the keys can be
re-named before merging to avoid collisions.)

**Rules** can be defined on the new global findings dictionary to create
alerts if necessary. Roughly speaking, these rules can check that (a)
certain dictionary keys do or do not contain entries, (b) no values
have been added or removed since the last run, or that (c) two lists
of entries overlap fully or do not overlap at all.

When rules are violated, **alerts** can be created. Alerts can have
four different severity levels. Alerts can then be used in the
**output** of the run, either to create reports or for immediate
notifications.

**Data** in the global findings list, and in inputs and outputs of
modules is loosely typed. This can be explained best using an example.
The following could be the global findings list after the `discover
Domains and IPs` module was run:

```YAML
DNS-Entries:
- domain: example.com
  ip: 93.184.216.34
- domain: example.com
  ip: 2606:2800:220:1:248:1893:25c8:1946
Domains:
- domain: example.com
IPs:
- ip: 93.184.216.34
- ip: 2606:2800:220:1:248:1893:25c8:1946
```

Under each key in the global findings list, a list of entries can be
found. Each entry contains one or more keys (`domain` and/or
`ip`). yesses expects that each member of a list contains the same
keys.

When a module expects an input having certain keys (which can be found
in the module description), inputs with additional keys can be used.
For example, the module `scan Ports` expects a range of IPs as input,
each entry having the key `ip`. Therefore, `DNS-Entries` or `IPs`
could be used as inputs for `scan Ports`. E.g., given the above global
findings list, the following would be valid:

```YAML
  - scan Ports:
      ips: use DNS-Entries
      (...)
```


## Configuration file ##

An example for a configuration file can be found in `docs/examples/example.yml`.

yesses configuration files are YAML files (input and output values
shown below and in the generated HTML files are shown in YAML syntax
as well).

Configuration files should adhere to the following top-level structure:

```YAML
data:                       # data: Predefined variables in the global findings list; can be used in the rest of the document
  Variable-Name:            # Custom variable name
    - value: some-value     # Custom variable values
    - value: another-value
  Another-Variable:

run:                        # run: List of steps to be run in each test
  - discover Step Name:     # Step names are documented below
      step-specific: 42     # Variables here depend on the individual steps
    find:                   # find: What output values to merge into the global findings list
      - Finding1 as New-Var # rename output to something else before merging (avoid collisions)
      - Finding2
    expect:                 # expect: rules on the output to create alerts
      - no New-Var, otherwise alert high
      - some Finding2, otherwise alert medium
      
  - scan Another Step:
      some-value: use Finding2 and New-Var  # re-use existing values from global findings

output:                     # output: one or more modules to create output
  - Template:               # output module name
      filename: some-filename.html
      template: templates/html/main.j2
      
```

### `data` ###

`data` is self-explanatory given the example above: It contains keys
and respective values that make up the initial global findings list.

### `run` ###

`run` contains the steps that are executed, in the order defined here,
within the yesses run. Each step is described using three keywords:
the step's identifier, `find`, and `expect`, as explained in the
following:

The **step's identifier** (like `scan Ports` or `discover Domains and
IPs`). Valid keys can be found in the module description below. Under
this key, input values for the respective module are defined. The keys
that can be used here can be found in the module description. Each key
can either contain the literal input data (e.g.: `protocols: ['tcp']`,
see also the examples below) or a `use`-expression. These start with
the keyword `use` and contain on or more keys from the global findings
list (multiple keys are separated by "and"). Example: `use DNS-Names
and My-Arbitrary-Input`.
    
**`find`**: This key defines which output names (see module
description) are merged into the global findings dictionary. Duplicate
names are not allowed, i.e., if a name already exists in the global
findings, an error message is shown. Keys can be renamed before
merging using an expression like `Key-Name as New-Key-Name`.
    
**`expect`**: This key defines the alerts triggered after the specific
step. Rules can refer to any entry in the global findings dictionary,
include the ones added by the step itself. Rules must adhere to one of the
following forms:

 1. (no|some) [new] FINDINGS, otherwise alert (informative|medium|high|very high)
 1. (no|some|all) FINDINGS1 in FINDINGS2, otherwise alert (informative|medium|high|very high)

The first form checks if findings exist (or do not exist). With the
`new` keyword, it checks if, compared to the last run, additional
entries have been found. yesses does this by creating a file with the
extension `.state` that stores the findings of the last run. If this
file is deleted between runs, all findings will be reported as new.

The second form checks if there is some, no, or a complete overlap
between the lists FINDINGS1 and FINDINGS2. Note that, if the entries
in these list contain different set of keys, only keys common to both
lists are matched.

### `output` ###

`output` defines what yesses does with the created alerts. See
[below](#user-content-output-modules) for a list of available modules
and their usage.

# Discovery and Scanning Modules #

The following modules are currently provided by yesses. For each
module, a short description in given plus a list of input and output
fields. The field names can be used in the yaml configuration file. 



## `scan Ports` ##
Uses `nmap` to scan for open ports.
    


### Examples ###

#### scan ports on Google DNS server ####
Configuration:
```YAML
  - scan Ports:
      ips: 
        - ip: '8.8.8.8'
      protocols: ['tcp']
    find:
      - Host-Ports
      - HTTPS-Ports
      - Other-Port-IPs
    expect:
      - no Host-Ports, otherwise alert high
```
Findings returned:
```YAML
HTTPS-Ports:
- &id001
  ip: 8.8.8.8
  port: 443
  protocol: tcp
Host-Ports:
- ip: 8.8.8.8
  port: 53
  protocol: tcp
- *id001
Other-Port-IPs:
- ip: 8.8.8.8
```
Alerts created (details hidden for brevity):

| Severity | Rule | #Findings |
|----------|------|-----------|
| Severity.HIGH | `no Host-Ports, otherwise alert high` | 1 |






### Inputs ###

| Name             | Description    | Required keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `ips` (required) | Required. IP range to scan (e.g., `use IPs`) | `ip` |
| `protocols`  | List of protocols (`udp`, `tcp`,...) in nmap's notations to scan. (Default: `tcp`) |  |
| `ports`  | Port range in nmap notation (e.g., '22,80,443-445'); default (None): 1000 most common ports as defined by nmap. |  |
| `named_ports`  | A mapping of names to ports. This can be used to control the output of this module. | `name`, `port` |
| `protocol_arguments`  | Command-line arguments to provide to nmap when scanning for a specific protocol. | `protocol`, `arguments` |




#### Default for `protocols` ####
```YAML
- tcp
```


#### Default for `ports` ####
```YAML
null
```


#### Default for `named_ports` ####
```YAML
- name: SSH
  port: 22
- name: HTTP
  port: 80
- name: HTTPS
  port: 443
```


#### Default for `protocol_arguments` ####
```YAML
- arguments: -sU
  protocol: udp
- arguments: -sT
  protocol: tcp
```



### Outputs ###

| Name             | Description    | Provided keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `Host-Ports` | Each open port on a scanned IP (with IP, protocol, and port) | `ip`, `protocol`, `port` |
| `*-Ports` | For certain protocols (SSH, HTTP, HTTPS), a list of hosts that have this port open (with IP, protocol, and port) | `ip`, `protocol`, `port` |
| `Other-Port-IPs` | List of IPs that have any other ports open. |  |



## `scan TLSSettings` ##
Uses the sslyze library to scan a webserver's TLS configuration and
compare it to the Mozilla TLS configuration profiles.

    


### Examples ###

#### Check TLS settings on badssl.com ####
Configuration:
```YAML
 - scan TLS Settings:
     domains:
      - domain: mozilla-intermediate.badssl.com
     tls_profile: intermediate
   find:
     - TLS-Profile-Mismatch-Domains
     - TLS-Validation-Fail-Domains
     - TLS-Vulnerability-Domains
     - TLS-Okay-Domains
     - TLS-Other-Error-Domains
   expect:
     - some TLS-Okay-Domains, otherwise alert medium
```
Findings returned:
```YAML
TLS-Okay-Domains: []
TLS-Other-Error-Domains: []
TLS-Profile-Mismatch-Domains:
- domain: mozilla-intermediate.badssl.com
  errors:
  - must not support "TLSv1"
  - must not support "TLSv1.1"
  - must not support "DHE-RSA-AES256-SHA"
  - must not support "ECDHE-RSA-DES-CBC3-SHA"
  - must not support "DES-CBC3-SHA"
  - must not support "DHE-RSA-AES256-SHA256"
  - must not support "ECDHE-RSA-AES256-SHA"
  - must not support "DHE-RSA-DES-CBC3-SHA"
  - must not support "ECDHE-RSA-AES128-SHA"
  - must not support "AES256-SHA"
  - must not support "AES256-GCM-SHA384"
  - must not support "AES128-GCM-SHA256"
  - must not support "DHE-RSA-AES128-SHA256"
  - must not support "ECDHE-RSA-AES256-SHA384"
  - must not support "AES128-SHA"
  - must not support "DHE-RSA-AES128-SHA"
  - must not support "AES128-SHA256"
  - must not support "EDH-RSA-DES-CBC3-SHA"
  - must not support "AES256-SHA256"
  - must not support "ECDHE-RSA-AES128-SHA256"
TLS-Validation-Fail-Domains: []
TLS-Vulnerability-Domains: []
```
Alerts created (details hidden for brevity):

| Severity | Rule | #Findings |
|----------|------|-----------|
| Severity.MEDIUM | `some TLS-Okay-Domains, otherwise alert medium` | 0 |






### Inputs ###

| Name             | Description    | Required keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `domains` (required) | List of domain names to scan. | `domain` |
| `tls_profile`  | The Mozilla TLS profile to test against (`old`, `intermediate`, or `new`). |  |




#### Default for `tls_profile` ####
```YAML
intermediate
```



### Outputs ###

| Name             | Description    | Provided keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `TLS-Profile-Mismatch-Domains` | Domains of servers that do not match the TLS profile. `errors` contains the list of deviations from the profile. | `domain`, `errors` |
| `TLS-Validation-Fail-Domains` | Domains of servers that presented an invalid certificate. `errors` contains the list of validation errors. | `domain`, `errors` |
| `TLS-Vulnerability-Domains` | Domains where a TLS vulnerability was detected. `errors` contains the list of vulnerabilities found. | `domain`, `errors` |
| `TLS-Okay-Domains` | Domains where no errors or vulnerabilities were found. | `domain` |
| `TLS-Other-Error-Domains` | Domains that could not be tested because of some error (e.g., a network error). `error` contains the error description. | `domain`, `error` |



## `scan TLSSettingsQualys` ##
Uses the Qualys SSL Labs TLS assessment service to determine the
security level of the TLS configuration. Only works for the HTTPS
standard port 443, therefore expects a list of domain names, not web
origins.

Note: The assessment service is provided free of charge by Qualys SSL
Labs, subject to their terms and conditions:
https://dev.ssllabs.com/about/terms.html
    



### Inputs ###

| Name             | Description    | Required keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `domains` (required) | List of domain names to scan. | `domain` |
| `allowed_grades`  | List of grades that are deemed acceptable. See https://ssllabs.com for details. (Default: `A` and `A+`. |  |




#### Default for `allowed_grades` ####
```YAML
- A
- A+
```



### Outputs ###

| Name             | Description    | Provided keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `TLS-Grade-Success` | Object containing information about IP/Host combinations that passed the SSL test with an acceptable grade. | `ip`, `domain`, `grade` |
| `TLS-Grade-Fail` | As above, but only IP/Host combinations that did not get an acceptable grade. | `ip`, `domain`, `grade` |
| `TLS-Grade-Error` | As above, but only IP/Host combinations that failed due to errors during the test. | `ip`, `domain`, `grade` |



## `scan WebSecuritySettings` ##
Scans web origins and finds:

  * web servers accepting insecure methods (like TRACE)
  * missing redirections to HTTPS and redirections from HTTPS to HTTP
  * disallowed headers (see below)
  * missing headers (see below)
  * missing cookie security features (see below)
  
Note: Only tests the web origins' root URLs.


##### Disallowed Headers #####
Disallowed headers are configured using objects that define the header name, optionally a regular expression that is matched against the headers' value, and a human-readable reason that explains the rule. 

Header names and values can be matched using regular expressions (matching is done using python3's `re.fullmatch`, case-insensitive).

Values can be matched using python expressions (see below).

If any disallowed header is found for a given URL, an entry for the respective URL is added in the result `Disallowed-Header-URLs`.

##### Required Headers #####

Defines headers that must be present in all responses. The `reason` keyword is not necessary for required header definitions.

If the `origin` keyword is present, the header is only required on origins that match the respective value (using `re.match`).

If `value_expr` is present, the contents are evaluated using python3's `eval()` function. Useful variables are:
 
  * `value`, which contains the header's contents as a string
  * `max_age`, which contains the `max_age` header property, e.g., for Strict-Transport-Security headers (if set)
  
##### Insecure Cookies #####

Cookies are only considered "secure" if they have the following properties:

  * On HTTPS URIs:
    * The name must start with the prefix `__Host-` or `__Secure-`.
    * The `secure` attribute must be set.
    * The `SameSite` attribute must be set.
  * The `HttpOnly` attribute must be set.

    


### Examples ###

#### Websecurity Settings of neverssl.com ####
Configuration:
```YAML
 - scan Web Security Settings:
     origins: 
       - url: http://neverssl.com
         ip: '143.204.208.22'
         domain: neverssl.com
   find:
     - Missing-HTTPS-Redirect-URLs
     - Redirect-to-non-HTTPS-URLs
     - Disallowed-Header-URLs
     - Missing-Header-URLs
     - Disallowed-Method-URLs
     - Insecure-Cookie-URLs
```
Findings returned:
```YAML
Disallowed-Header-URLs: []
Disallowed-Method-URLs: []
Insecure-Cookie-URLs: []
Missing-HTTPS-Redirect-URLs:
- error: no redirection encountered
  ip: 143.204.208.22
  url: http://neverssl.com/
Missing-Header-URLs: []
Redirect-to-non-HTTPS-URLs: []
```





### Inputs ###

| Name             | Description    | Required keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `origins` (required) | List of web origins to scan. | `url`, `domain`, `ip` |
| `disallowed_methods`  | List of methods that should be rejected by web servers. |  |
| `disallowed_headers`  | Objects defining headers that are not allowed (see description). | `header` |
| `required_headers`  | Objects defining headers that are required (see description). | `header` |




#### Default for `disallowed_methods` ####
```YAML
- TRACE
- TRACK
- CONNECT
```


#### Default for `disallowed_headers` ####
```YAML
- header: Access-Control-.*
  reason: CORS must be disabled
- header: Server
  reason: Server headers must not contain version information
  value: .* .*[0-9].*
```


#### Default for `required_headers` ####
```YAML
- header: Strict-Transport-Security
  origin: 'https:'
  reason: STS header must be set and be valid for at least one year
  value_expr: max_age >= 31536000
- header: X-Frame-Options
  origin: 'https:'
  value: DENY
- header: X-Content-Type-Options
  origin: 'https:'
  value: nosniff
- header: Referrer-Policy
  origin: 'https:'
- header: Content-Security-Policy
  origin: 'https:'
- header: Expect-CT
  origin: 'https:'
  value_expr: value.startswith("enforce,") and max_age > 86400
```



### Outputs ###

| Name             | Description    | Provided keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `Missing-HTTPS-Redirect-URLs` | HTTP URLs which do not redirect to HTTPS. | `url`, `ip`, `error` |
| `Redirect-to-non-HTTPS-URLs` | URLs which redirect to HTTP URLs. | `url`, `ip`, `error` |
| `Disallowed-Header-URLs` | URLs that set disallowed headers. | `url`, `ip`, `errors` |
| `Missing-Header-URLs` | URLs that miss headers. | `url`, `ip`, `errors` |
| `Disallowed-Method-URLs` | URLs where disallowed methods do not trigger an error. | `url`, `ip`, `errors` |
| `Insecure-Cookie-URLs` | URLs where cookie settings are not sufficient. | `url`, `ip`, `errors` |





## `discover DomainsAndIPs` ##
Based on domain names as "seeds", tries to find new domain names by
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

    


### Examples ###

#### discover DNS details of example.com ####
Configuration:
```YAML
  - discover Domains and IPs:
      seeds:
        - domain: example.com
      resolvers: 
        - ip: '1.1.1.1'
    find:
      - IPs
      - Domains
      - DNS-Entries
```
Findings returned:
```YAML
DNS-Entries:
- domain: example.com
  ip: 93.184.216.34
- domain: example.com
  ip: 2606:2800:220:1:248:1893:25c8:1946
Domains:
- domain: example.com
IPs:
- ip: 2606:2800:220:1:248:1893:25c8:1946
- ip: 93.184.216.34
```





### Inputs ###

| Name             | Description    | Required keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `seeds` (required) | List of initial domains to start search from | `domain` |
| `resolvers`  | List of DNS resolvers to use. Default (empty list): System DNS resolvers. | `ip` |




#### Default for `resolvers` ####
```YAML
[]
```



### Outputs ###

| Name             | Description    | Provided keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `Domains` | List of domains found | `domain` |
| `IPs` | List of IPs found | `ip` |
| `DNS-Entries` | Pairs of (domain, IP) associations | `domain`, `ip` |
| `Ignored-Domains` | CNAME targets that are not a subdomain of one of the seeding domains; these are not expanded further and are not contained in the other results. | `domain` |



## `discover TLSCertificates` ##
Queries Certificate Transparency logs (using https://crt.sh) for
existing TLS certificates for given domains and their subdomains.

Note: The output may contain wildcards, e.g., '*.example.com'.

    


### Examples ###

#### list certificates of example.com ####
Configuration:
```YAML
  - discover TLS Certificates:
      seeds:
        - domain: example.com
    find:
      - TLS-Names
      - TLS-Certificates
```
Findings returned:
```YAML
TLS-Certificates:
- certificate_id: https://crt.sh/?id=24560621
  certificate_url: https://crt.sh/?id=24560621
- certificate_id: https://crt.sh/?id=24564717
  certificate_url: https://crt.sh/?id=24564717
- certificate_id: https://crt.sh/?id=984858191
  certificate_url: https://crt.sh/?id=984858191
- certificate_id: https://crt.sh/?id=10557607
  certificate_url: https://crt.sh/?id=10557607
- certificate_id: https://crt.sh/?id=5857507
  certificate_url: https://crt.sh/?id=5857507
- certificate_id: https://crt.sh/?id=987119772
  certificate_url: https://crt.sh/?id=987119772
- certificate_id: https://crt.sh/?id=24560643
  certificate_url: https://crt.sh/?id=24560643
- certificate_id: https://crt.sh/?id=24558997
  certificate_url: https://crt.sh/?id=24558997
TLS-Names:
- domain: m.example.com
- domain: support.example.com
- domain: dev.example.com
- domain: products.example.com
- domain: '*.example.com'
- domain: www.example.com
```





### Inputs ###

| Name             | Description    | Required keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `seeds` (required) | List of domains for search. Certificates for domains in this list and their subdomains will be found | `domain` |





### Outputs ###

| Name             | Description    | Provided keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `TLS-Names` | DNS names found in certificates (may include wildcards, such as `*.example.com`). | `domain` |
| `TLS-Certificates` | Unique identifiers for found TLS certificates; also links to more information about the certificates. `certificate_id` and `certificate_url` have the same content in this module, as the URI is also used to uniquely identify the certificate. | `certificate_id`, `certificate_url` |



## `discover Webservers` ##
Scans an IP range for web servers (on standard HTTP and HTTPs
ports); combines a list of IPs with a list of domains to use for the
Host header in web requests.

    


### Examples ###

#### detect webservers on example.com ####
Configuration:
```YAML
  - discover Webservers:
      ips: 
        - ip: '93.184.216.34'
        - ip: '2606:2800:220:1:248:1893:25c8:1946'
      domains:
        - domain: example.com
        - domain: dev.example.com
    find:
      - Insecure-Origins
      - Secure-Origins
      - TLS-Domains
```
Findings returned:
```YAML
Insecure-Origins:
- domain: example.com
  ip: 93.184.216.34
  url: http://example.com/
- domain: dev.example.com
  ip: 93.184.216.34
  url: http://dev.example.com/
- domain: example.com
  ip: 2606:2800:220:1:248:1893:25c8:1946
  url: http://example.com/
- domain: dev.example.com
  ip: 2606:2800:220:1:248:1893:25c8:1946
  url: http://dev.example.com/
Secure-Origins:
- domain: example.com
  ip: 93.184.216.34
  url: https://example.com/
- domain: example.com
  ip: 2606:2800:220:1:248:1893:25c8:1946
  url: https://example.com/
TLS-Domains:
- domain: example.com
```





### Inputs ###

| Name             | Description    | Required keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `ips` (required) | IP range to scan (e.g., `use HTTP-IPs and HTTPS-IPs`) | `ip` |
| `domains` (required) | Domain names to try on these IPs | `domain` |






### Outputs ###

| Name             | Description    | Provided keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `Insecure-Origins` | HTTP origins | `domain`, `url`, `ip` |
| `Secure-Origins` | as above, but for HTTPS | `domain`, `url`, `ip` |
| `TLS-Domains` | List of domains with HTTPS servers | `domain` |





# Output Modules

Output modules take the alerts created from the findings of the
discovery and scanning modules and produce some kind of output - a
file, a notification, or potentially other forms of output.

## `Template`

This module uses a jinja2 template to create output, for example, an HTML summary of the alerts.


Parameters:

  * `template`: defines the jinja2 template that is to be used to create the output.
  * `filename`: where the output is written to. Placeholders as in [python's `strftime()` function](https://docs.python.org/3/library/datetime.html#strftime-and-strptime-behavior) are evaluated. For example, `yesses-report-%Y-%m-%d-%H%M%S.html` would be converted to a filename like `yesses-report-2019-10-07-174140.html`.

Both filenames can be relative paths (evaluated relative to the
working directory) or absolute paths.


## `Slack`

Sends a slack notification to one or more recipients. The notification
contains a summary of the alerts (grouped by severity).

Parameters:

  * `channels`: List of channel identifiers to send the notification to. Can also be user identifiers (which can be retrieved from the Slack user interface) to send the notification to individual users.
  * `token`: A valid slack bot API token. The token can alternatively be provided in an environment variable `YESSES_SLACK_TOKEN`.
