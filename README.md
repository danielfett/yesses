# BogoSec #

Simple tool to enumerate domains and IPs and test those domains and
IPs for basic network and web security properties.

## Modules ##

### `expect` ###
Expects arguments of the form "no added X, otherwise action args".

### `discover Domains and IPs` ###
Inputs:
| Field   | Contents                                     |
|---------|----------------------------------------------|
| `seeds` | List of initial domains to start search from |

Returns:

| Field         | Contents                           |
|---------------|------------------------------------|
| `Domains`     | List of domains found              |
| `IPs`         | List of IPs found                  |
| `DNS-Entries` | Pairs of (domain, IP) associations |

### `scan Ports` ###
Inputs:
| Field       | Contents                                                              |
|-------------|-----------------------------------------------------------------------|
| `protocols` | List of protocols (`udp`, `tcp`,...) in nmap's notations to scan      |
| `ports`     | Port range in nmap notation (e.g., '22,80,443-445'); default: 0-65535 |
| `ips`       | IP range to scan (e.g., `use IPs`)                                    |

Returns:

| Field         | Contents                                                                         |
|---------------|----------------------------------------------------------------------------------|
| `Host-Ports`  | Tuples (ip, protocol, port) for each open port on a scanned IP                   |
| `$X-IPs`      | For certain protocols (SSH, HTTP, HTTPS), a list of IPs that have this port open |

### `scan Webservers` ###

Inputs:
| Field         | Contents                                              |
|---------------|-------------------------------------------------------|
| `ips`         | IP range to scan (e.g., `use HTTP-IPs and HTTPS-IPs`) |
| `domains`     | Domain names to try on these IPs                      |
| `http_ports`  | Ports to try to connect to without TLS (default: 80)  |
| `https_ports` | Ports to try to connect to with TLS (default: 443)    |

Returns:

| Field         | Contents                                                                         |
|---------------|----------------------------------------------------------------------------------|
| `Host-Ports`  | Tuples (ip, protocol, port) for each open port on a scanned IP                   |
| `$X-IPs`      | For certain protocols (SSH, HTTP, HTTPS), a list of IPs that have this port open |
