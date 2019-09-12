# yesses #

Simple tool to enumerate domains and IPs and test those domains and
IPs for basic network and web security properties.

yesses provides a number of modules that each perform a certain task.
For example, the module `discover Domains and IPs` queries DNS servers
for IP addresses. Each module has a number of defined inputs (in this
case, for example, domain names) and outputs (e.g., IP addresses and
domain names expanded from CNAMEs). 

Modules can be combined by feeding the output of one module into the
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



## Usage ##

```
usage: run.py [-h] [--verbose] [--resume] [--repeat N] [--fresh] configfile

Tool to scan for network and web security features

positional arguments:
  configfile     Config file in yaml format

optional arguments:
  -h, --help     show this help message and exit
  --verbose, -v  Increase debug level
  --resume, -r   Resume scanning from existing resumefile
  --repeat N     Repeat last N steps of run (for debugging). Will inhibit
                 warnings of duplicate output variables.
  --fresh, -f    Do not use existing state files. Usage of this required when
                 datastructures in this application changed.

```



## Configuration ##

[todo]

### `expect` ###
Expects arguments of the form "no added X, otherwise action args".

## Modules ##

The following modules are currently provided by yesses. For each
module, a short description in given plus a list of input and output
fields. The field names can be used in the yaml configuration file. 



### `scan Ports` ###
Uses `nmap` to scan for open ports.
    

#### Inputs ####

| Name             | Description    | Required keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `ips` (required) | Required. IP range to scan (e.g., `use IPs`) | `ip` |
| `protocols`  | List of protocols (`udp`, `tcp`,...) in nmap's notations to scan. (Default: `tcp`) |  |
| `ports`  | Port range in nmap notation (e.g., '22,80,443-445'); default (None): 1000 most common ports as defined by nmap. |  |




##### Default for `protocols` #####
```
- tcp
```


##### Default for `ports` #####
```
null
```



#### Outputs ####

| Name             | Description    | Provided keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `Host-Ports` | Each open port on a scanned IP | `ip`, `protocol`, `port` |
| `*-IPs` | For certain protocols (SSH, HTTP, HTTPS), a list of IPs that have this port open | `ip` |
| `Other-Port-IPs` | List of IPs that have any other ports open. |  |



### `scan TLSSettings` ###
Uses the sslyze library to scan a webserver's TLS configuration and
compare it to the Mozilla TLS configuration profiles.

    

#### Inputs ####

| Name             | Description    | Required keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `domains` (required) | List of domain names to scan. | `domain` |
| `tls_profile`  | The Mozilla TLS profile to test against (`old`, `intermediate`, or `new`). |  |




##### Default for `tls_profile` #####
```
intermediate
```



#### Outputs ####

| Name             | Description    | Provided keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `TLS-Profile-Mismatch-Domains` | Domains of servers that do not match the TLS profile. `errors` contains the list of deviations from the profile. | `domain`, `errors` |
| `TLS-Validation-Fail-Domains` | Domains of servers that presented an invalid certificate. `errors` contains the list of validation errors. | `domain`, `errors` |
| `TLS-Vulnerability-Domains` | Domains where a TLS vulnerability was detected. `errors` contains the list of vulnerabilities found. | `domain`, `errors` |
| `TLS-Okay-Domains` | Domains where no errors or vulnerabilities were found. | `domain` |
| `TLS-Other-Error-Domains` | Domains that could not be tested because of some error (e.g., a network error). `error` contains the error description. | `domain`, `error` |



### `scan TLSSettingsQualys` ###
Uses the Qualys SSL Labs TLS assessment service to determine the
security level of the TLS configuration. Only works for the HTTPS
standard port 443, therefore expects a list of domain names, not web
origins.

Note: The assessment service is provided free of charge by Qualys SSL
Labs, subject to their terms and conditions:
https://dev.ssllabs.com/about/terms.html
    

#### Inputs ####

| Name             | Description    | Required keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `domains` (required) | List of domain names to scan. | `domain` |
| `allowed_grades`  | List of grades that are deemed acceptable. See https://ssllabs.com for details. (Default: `A` and `A+`. |  |




##### Default for `allowed_grades` #####
```
- A
- A+
```



#### Outputs ####

| Name             | Description    | Provided keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `TLS-Grade-Success` | Object containing information about IP/Host combinations that passed the SSL test with an acceptable grade. | `ip`, `domain`, `grade` |
| `TLS-Grade-Fail` | As above, but only IP/Host combinations that did not get an acceptable grade. | `ip`, `domain`, `grade` |
| `TLS-Grade-Error` | As above, but only IP/Host combinations that failed due to errors during the test. | `ip`, `domain`, `grade` |



### `scan WebSecuritySettings` ###
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

    

#### Inputs ####

| Name             | Description    | Required keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `origins` (required) | List of web origins to scan. | `uri`, `domain`, `ip` |
| `disallowed_methods`  | List of methods that should be rejected by web servers. |  |
| `disallowed_headers`  | Objects defining headers that are not allowed (see description). | `header` |
| `required_headers`  | Objects defining headers that are required (see description). | `headers` |




##### Default for `disallowed_methods` #####
```
- TRACE
- TRACK
- CONNECT
```


##### Default for `disallowed_headers` #####
```
- header: Access-Control-.*
  reason: CORS must be disabled
- header: Server
  reason: Server headers must not contain version information
  value: .* .*[0-9].*
```


##### Default for `required_headers` #####
```
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



#### Outputs ####

| Name             | Description    | Provided keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `Missing-HTTPS-Redirect-URLs` | HTTP URLs which do not redirect to HTTPS. | `uri`, `ip`, `error` |
| `Redirect-to-non-HTTPS-URLs` | URLs which redirect to HTTP URLs. | `uri`, `ip`, `error` |
| `Disallowed-Header-URLs` | URLs that set disallowed headers. | `uri`, `ip`, `errors` |
| `Missing-Header-URLs` | URLs that miss headers. | `uri`, `ip`, `errors` |
| `Disallowed-Method-URLs` | URLs where disallowed methods do not trigger an error. | `uri`, `ip`, `errors` |
| `Insecure-Cookie-URLs` | URLs where cookie settings are not sufficient. | `uri`, `ip`, `error` |





### `discover DomainsAndIPs` ###
Based on domain names as "seeds", tries to find new domain names by
guessing expansions for wildcards and expanding CNAMEs. Finds IP
addresses from A and AAAA records.

#### Examples ####
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

    

#### Inputs ####

| Name             | Description    | Required keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `seeds` (required) | List of initial domains to start search from | `domain` |
| `resolvers`  | List of DNS resolvers to use. Default (empty list): System DNS resolvers. | `ip` |




##### Default for `resolvers` #####
```
[]
```



#### Outputs ####

| Name             | Description    | Provided keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `Domains` | List of domains found | `domain` |
| `IPs` | List of IPs found | `ip` |
| `DNS-Entries` | Pairs of (domain, IP) associations | `domain`, `ip` |
| `Ignored-Domains` | CNAME targets that are not a subdomain of one of the seeding domains; these are not expanded further and are not contained in the other results. | `domain` |



### `discover TLSCertificates` ###
Queries Certificate Transparency logs (using https://crt.sh) for
existing TLS certificates for given domains and their subdomains.

    

#### Inputs ####

| Name             | Description    | Required keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `seeds` (required) | List of domains for search. Certificates for domains in this list and their subdomains will be found | `domain` |





#### Outputs ####

| Name             | Description    | Provided keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `TLS-Names` | DNS names found in certificates (may include wildcards, such as `*.example.com`). | `domain` |
| `TLS-Certificates` | Unique identifiers for found TLS certificates; also links to more information about the certificates. `certificate_id` and `certificate_url` have the same content in this module, as the URI is also used to uniquely identify the certificate. | `certificate_id`, `certificate_url` |



### `discover Webservers` ###
Scans an IP range for web servers (on standard HTTP and HTTPs
ports); combines a list of IPs with a list of domains to use for the
Host header in web requests.

    

#### Inputs ####

| Name             | Description    | Required keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `ips` (required) | IP range to scan (e.g., `use HTTP-IPs and HTTPS-IPs`) | `ip` |
| `domains` (required) | Domain names to try on these IPs | `domain` |






#### Outputs ####

| Name             | Description    | Provided keys                                            |
|------------------|----------------|----------------------------------------------------------|
| `Web-Origins` | HTTP origins | `domain`, `url`, `ip` |
| `TLS-Web-Origins` | as above, but for HTTPS | `domain`, `url`, `ip` |
| `TLS-Domains` | List of domains with HTTPS servers | `domain` |



