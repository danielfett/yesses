# yesses #

Simple tool to enumerate domains and IPs and test those domains and
IPs for basic network and web security properties.

## Usage ##

```
usage: run.py [-h] [--verbose] [--resume] [--repeat N] configfile

Tool to scan for network and web security features

positional arguments:
  configfile     Config file in yaml format

optional arguments:
  -h, --help     show this help message and exit
  --verbose, -v  Increase debug level
  --resume, -r   Resume scanning from existing resumefile
  --repeat N     Repeat last N steps of run (for debugging). Will inhibit
                 warnings of duplicate output variables.
```

## Configuration file ##

[todo]

### `expect` ###
Expects arguments of the form "no added X, otherwise action args".

## Modules ##


### `discover TLS Certificates` ###
Queries Certificate Transparency logs for existing TLS certificates
for given domains and their subdomains.

#### Inputs ####
| Field   | Contents                    |
|---------|-----------------------------|
| `seeds` | List of domains for search. |

#### Returns ####
| Field              | Contents                                                                                              |
|--------------------|-------------------------------------------------------------------------------------------------------|
| `TLS-Names`        | DNS names found in certificates (may include wildcards, such as `*.example.com`).                                                                      |
| `TLS-Certificates` | Unique identifiers for found TLS certificates; also links to more information about the certificates. |
|                    |                                                                                                       |

#### Example ####
```
  - discover TLS Certificates:
      seeds: use Domain-Seeds
    find:
      - TLS-Names
      - TLS-Certificates
    expect:
      - no added TLS-Names, otherwise alert medium
      - no added TLS-Certificates, otherwise alert medium
```

### `discover Domains and IPs` ###
Based on domain names as "seeds", tries to find new domain names by
guessing expansions for wildcards and expanding CNAMEs. Finds IP
addresses from A and AAAA records.

#### Inputs ####
| Field       | Contents                                     |
|-------------|----------------------------------------------|
| `seeds`     | List of initial domains to start search from |
| `resolvers` | List of DNS resolvers to use                 |


#### Returns ####
| Field         | Contents                           |
|---------------|------------------------------------|
| `Domains`     | List of domains found              |
| `IPs`         | List of IPs found                  |
| `DNS-Entries` | Pairs of (domain, IP) associations |

#### Example ####
This examples expands domains from a list of domain seeds and the TLS names found with `discover TLS Certificates`. The alerting assumes that a whitelist of IP addresses (`Good-IPs`) exists.
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

### `scan Ports` ###
Uses `nmap` to scan for open ports.

#### Inputs ####

| Field       | Contents                                                                           |
|-------------|------------------------------------------------------------------------------------|
| `ips`       | Required. IP range to scan (e.g., `use IPs`)                                       |
| `protocols` | List of protocols (`udp`, `tcp`,...) in nmap's notations to scan. (Default: `tcp`) |
| `ports`     | Port range in nmap notation (e.g., '22,80,443-445'); default: 0-65535              |

#### Returns ####

| Field            | Contents                                                                         |
|------------------|----------------------------------------------------------------------------------|
| `Host-Ports`     | Tuples (ip, protocol, port) for each open port on a scanned IP                   |
| `$X-IPs`         | For certain protocols (SSH, HTTP, HTTPS), a list of IPs that have this port open |
| `Other-Port-IPs` | List of IPs that have any other ports open.                                      |


#### Example ####

```
  - scan Ports:
      protocols:
        - tcp
      ips: use IPs
    find:
      - Host-Ports
      - HTTP-IPs
      - HTTPS-IPs
    expect:
      - no added Host-Ports, otherwise alert high
```

### `scan Webservers` ###

Scans an IP range for web servers (on standard HTTP and HTTPs ports);
combines a list of IPs with a list of domains to use for the Host
header in web requests.

#### Inputs ####

| Field         | Contents                                              |
|---------------|-------------------------------------------------------|
| `ips`         | IP range to scan (e.g., `use HTTP-IPs and HTTPS-IPs`) |
| `domains`     | Domain names to try on these IPs                      |

#### Returns ####
| Field             | Contents                                |
|-------------------|-----------------------------------------|
| `Web-Origins`     | HTTP origins (tuples (url, domain, ip)) |
| `TLS-Web-Origins` | as above, but for HTTPS                 |
| `TLS-Domains`     | List of domains with HTTPS servers      |

#### Example ####
```
  - scan Webservers:
      ips: use HTTP-IPs and HTTPS-IPs
      domains: use Domains
    find:
      - Web-Origins
      - TLS-Web-Origins
      - TLS-Domains
    expect:
      - no added Web-Origins, otherwise alert high
```

### `scan TLS Settings`
Uses the Qualys SSL Labs TLS assessment service to determine the
security level of the TLS configuration. Only works for the HTTPS
standard port 443, therefore expects a list of domain names, not web
origins.

Note: The assessment service is provided free of charge by Qualys SSL
Labs, subject to their terms and conditions:
https://dev.ssllabs.com/about/terms.html

#### Inputs ####
| Field            | Contents                                                                                                 |
|------------------|----------------------------------------------------------------------------------------------------------|
| `domains`        | List of domain names to scan.                                                                            |
| `allowed_grades` | List of grades that are deemed acceptable. See https://ssllabs.com for details. (Default: `A` and `A+`.) |

#### Returns ####
| Field                   | Contents                                                                                                                                      |
|-------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------|
| `TLS-Grade-Success`     | Object (with properties `IP` and `Host`) containing information about IP/Host combinations that passed the SSL test with an acceptable grade. |
| `TLS-Grade-Fail`        | As above, but only IP/Host combinations that did not get an acceptable grade.                                                                 |
| `TLS-Grade-Error`       | As above, but only IP/Host combinations that failed due to errors during the test.                                                            |
| `TLS-Grade-Success-IPs` | As above, but only IP addresses.                                                                                                              |
| `TLS-Grade-Fail-IPs`    | As above, but only IP addresses.                                                                                                              |
| `TLS-Grade-Error-IPs`   | As above, but only IP addresses.                                                                                                              |

#### Example ####

```
  - scan TLS Settings:
      domains: use TLS-Domains
      allowed_grades:
        - 'A'
        - 'A+'
    find:
      - TLS-Grade-Error
      - TLS-Grade-Fail
      - TLS-Grade-Success-IPs
    expect:
      - no TLS-Grade-Fail, otherwise alert high
      - no TLS-Grade-Error, otherwise alert high
      - all TLS-Grade-Success-IPs in Good-IPs, otherwise alert high
```

### `scan Web Security Settings` ###



#### Inputs ####
Scans web origins and finds:

  * web servers accepting insecure methods (like TRACE)
  * missing redirections to HTTPS and redirections from HTTPS to HTTP
  * disallowed headers (see below)
  * missing headers (see below)
  * missing cookie security features (see below)
  
Note: Only tests the web origins' root URLs.

| Field                | Contents                                                   |
|----------------------|------------------------------------------------------------|
| `origins`            | List of web origins (tuples (url, domain, ip)) to scan.    |
| `disallowed_methods` | List of methods that should be rejected by web servers.    |
| `disallowed_headers` | Objects defining headers that are not allowed (see below). |
| `required_headers`   | Objects defining headers that are required.                |

##### Disallowed Methods #####

Default: `['TRACE', 'TRACK', 'DELETE', 'PUT', 'CONNECT']`

##### Disallowed Headers #####
Disallowed headers are configured using objects that define the header name, optionally a regular expression that is matched against the headers' value, and a human-readable reason that explains the rule. 

Header names and values can be matched using regular expressions (matching is done using python3's `re.fullmatch`, case-insensitive).

Default:

```
- header: Access-Control-.*
  reason: CORS must be disabled
- header: Server
  reason: Server headers must not contain version information
  value: .* .*[0-9].*
```

Values can be matched using python expressions (see below).

If any disallowed header is found for a given URL, an entry for the respective URL is added in the result `Disallowed-Header-URLs`.

##### Required Headers #####

Defines headers that must be present in all responses. The `reason` keyword is not necessary for required header definitions.

Default:

```
- header: 'Strict-Transport-Security:'
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


#### Returns ####
| Field                         | Contents                                                                              |
|-------------------------------|---------------------------------------------------------------------------------------|
| `Non-TLS-URLs`                | List of URLs that are encountered (e.g., during redirections) which do not use HTTPS. |
| `Missing-HTTPS-Redirect-URLs` | HTTP URLs which do not redirect to HTTPS.                                             |
| `Redirect-to-non-HTTPS-URLs`  | URLs which redirect to HTTP URLs.                                                     |
| `Disallowed-Header-URLs`      | URLs that set disallowed headers.                                                     |
| `Missing-Header-URLs`         | URLs that miss headers.                                                               |
| `Disallowed-Method-URLs`      | URLs where disallowed methods do not trigger an error.                                |
| `Insecure-Cookie-URLs`        | URLs where cookie settings are not sufficient.                                        |

## Output Control ##

Using the `output` section in the configuration file, the output of yesses can be controlled. Please refer to the [Python Configuration Dictionary Schema][1] for details. yesses's alert levels are defined as `ALERT_LOW`, `ALERT_MEDIUM`, `ALERT_HIGH`, and `ALERT_VERY_HIGH`.

### Example ###

```
output:
  version: 1
  disable_existing_loggers: no
  formatters:
    default:
      format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    alert:
      format: "[%(asctime)s]\n%(levelname)s: %(message)s"
  root:
    level: DEBUG
    handlers:
      - file_debug
      - file_alerts
  handlers:
    file_debug:
      class : logging.FileHandler
      formatter: default
      filename: yesses.debug.log
      level   : DEBUG
    file_alerts:
      class : logging.FileHandler
      formatter: alert
      filename: yesses.alerts.log
      level   : ALERT_LOW
```

[1]: https://docs.python.org/3/library/logging.config.html#logging-config-dictschema
