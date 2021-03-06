import requests
import logging
from yesses.utils import force_ip_connection
import re
from yesses.module import YModule, YExample

log = logging.getLogger("scan/websecuritysettings")


class WebSecuritySettings(YModule):
    """Scans web origins and finds:

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

    """

    DISALLOWED_METHODS = ["TRACE", "TRACK", "CONNECT"]

    DISALLOWED_HEADERS = [
        {"header": "Access-Control-.*", "reason": "CORS must be disabled",},
        {
            "header": "Server",
            "value": ".* .*[0-9].*",
            "reason": "Server headers must not contain version information",
        },
    ]

    REQUIRED_HEADERS = [
        {
            "header": "Strict-Transport-Security",
            "value_expr": "max_age >= 31536000",
            "reason": "STS header must be set and be valid for at least one year",
            "origin": "https:",
        },
        {"header": "X-Frame-Options", "value": "DENY", "origin": "https:",},
        {"header": "X-Content-Type-Options", "value": "nosniff", "origin": "https:",},
        {"header": "Referrer-Policy", "origin": "https:",},
        {"header": "Content-Security-Policy", "origin": "https:",},
        {
            "header": "Expect-CT",
            "value_expr": 'value.startswith("enforce,") and max_age > 86400',
            "origin": "https:",
        },
    ]

    INPUTS = {
        "origins": {
            "required_keys": ["url", "domain", "ip"],
            "description": "List of web origins to scan.",
        },
        "disallowed_methods": {
            "required_keys": None,
            "description": "List of methods that should be rejected by web servers.",
            "default": DISALLOWED_METHODS,
        },
        "disallowed_headers": {
            "required_keys": ["header"],
            "description": "Objects defining headers that are not allowed (see description).",
            "default": DISALLOWED_HEADERS,
        },
        "required_headers": {
            "required_keys": ["header"],
            "description": "Objects defining headers that are required (see description).",
            "default": REQUIRED_HEADERS,
        },
    }

    OUTPUTS = {
        "Missing-HTTPS-Redirect-URLs": {
            "provided_keys": ["url", "ip", "error"],
            "description": "HTTP URLs which do not redirect to HTTPS.",
        },
        "Redirect-to-non-HTTPS-URLs": {
            "provided_keys": ["url", "ip", "error"],
            "description": "URLs which redirect to HTTP URLs.",
        },
        "Disallowed-Header-URLs": {
            "provided_keys": ["url", "ip", "errors"],
            "description": "URLs that set disallowed headers.",
        },
        "Missing-Header-URLs": {
            "provided_keys": ["url", "ip", "errors"],
            "description": "URLs that miss headers.",
        },
        "Disallowed-Method-URLs": {
            "provided_keys": ["url", "ip", "errors"],
            "description": "URLs where disallowed methods do not trigger an error.",
        },
        "Insecure-Cookie-URLs": {
            "provided_keys": ["url", "ip", "errors"],
            "description": "URLs where cookie settings are not sufficient.",
        },
    }

    EXAMPLES = [
        YExample(
            "Websecurity Settings of neverssl.com",
            """
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
""",
        )
    ]

    def run(self):
        for origin in self.origins:
            self.run_checks(**origin)

    def run_checks(self, url, domain, ip):
        log.info(f"Now checking {domain} on IP {ip}")
        with force_ip_connection(domain, ip):
            try:
                log.debug(f"GET {url} with IP {ip}")
                response = requests.get(url, timeout=10, stream=True)
            except requests.exceptions.RequestException as e:
                log.debug(f"Exception {e} on {url}, ip={ip}")
            else:
                if url.startswith("http://"):
                    self.check_http_settings(ip, response)
                self.check_https_settings(ip, response)
                response.close()

            self.check_disallowed_methods(url, ip)

    def check_disallowed_methods(self, url, ip):
        # check webserver's reaction to an illegal method first.
        status_code_on_error = None
        try:
            response = requests.request("YESSES", url, timeout=10)
        except requests.exceptions.RequestException as e:
            log.debug(f"Exception {e} on {url}, ip={ip}")
        else:
            status_code_on_error = response.status_code

        found_disallowed_methods = []
        for method in self.disallowed_methods:
            try:
                log.debug(f"{method} {url} with IP {ip}")
                response = requests.request(method, url, timeout=10)
            except requests.exceptions.RequestException as e:
                log.debug(f"Exception {e} on {url}, ip={ip}")
            else:
                status = response.status_code
                if status < 400:
                    if status == status_code_on_error:
                        found_disallowed_methods.append(
                            f"may support forbidden method {method} (status code {status})"
                        )
                    else:
                        found_disallowed_methods.append(
                            f"supports forbidden method {method}"
                        )

        if found_disallowed_methods:
            self.results["Disallowed-Method-URLs"].append(
                {"url": url, "ip": ip, "errors": found_disallowed_methods,}
            )

    def check_http_settings(self, ip, response):
        if len(response.history) == 0:
            self.results["Missing-HTTPS-Redirect-URLs"].append(
                {"url": response.url, "ip": ip, "error": "no redirection encountered"}
            )

    def check_https_settings(self, ip, response):
        chain = [sr.url for sr in response.history + [response]]
        for step_uri in chain[1:]:
            if not step_uri.startswith("https://"):
                error = f"got redirections to non-HTTPS-URLs; redirection chain: {' → '.join(chain)}"
                self.results["Redirect-to-non-HTTPS-URLs"].append(
                    {"url": chain[0], "ip": ip, "error": error,}
                )
                break

        self.check_headers(ip, response)

    def match_header(self, url, rule, header, value):
        header = header.strip()
        value = value.strip()
        if re.fullmatch(rule["header"], header, re.IGNORECASE):
            if "value" in rule:
                if re.fullmatch(rule["value"], value, re.IGNORECASE):
                    return True
                else:
                    return False
            elif "value_expr" in rule:
                # check if max_age attribute is set
                match = re.search("max-age=([0-9]+)", value, re.IGNORECASE)
                if match:
                    max_age = int(match.group(1))
                else:
                    max_age = 0
                return eval(rule["value_expr"])
            else:
                return True

        return None

    def check_headers(self, ip, response):
        try:
            actual_ip = response.raw._connection.sock.socket.getsockname()[0]
        except AttributeError:
            try:
                actual_ip = response.raw._connection.sock.getsockname()[0]
            except:
                actual_ip = None

        self.check_disallowed_headers(actual_ip, response)
        self.check_missing_headers(actual_ip, response)
        self.check_insecure_cookies(actual_ip, response)

    def check_disallowed_headers(self, actual_ip, response):
        found_disallowed_headers = []
        for rule in self.disallowed_headers:
            for header, value in response.headers.items():
                match = self.match_header(response.url, rule, header, value)
                if match is True:
                    found_disallowed_headers.append(
                        f"illegal header {header} (with value {value}): {rule['reason']}"
                    )

        if found_disallowed_headers:
            self.results["Disallowed-Header-URLs"].append(
                {
                    "url": response.url,
                    "ip": actual_ip,
                    "errors": found_disallowed_headers,
                }
            )

    def check_missing_headers(self, actual_ip, response):
        found_missing_headers = []
        for rule in self.required_headers:
            if "origin" in rule:
                if not re.match(rule["origin"], response.url):
                    continue

            for header, value in response.headers.items():
                match = self.match_header(response.url, rule, header, value)
                if match is True:
                    break
            else:
                if "value" in rule:
                    text = f" with value '{rule['value']}'"
                elif "value_expr" in rule:
                    text = f" matching expression '{rule['value_expr']}'"
                else:
                    text = ""
                found_missing_headers.append(
                    f"missing header: '{rule['header']}' {text}"
                )

        if found_missing_headers:
            self.results["Missing-Header-URLs"].append(
                {"url": response.url, "ip": actual_ip, "errors": found_missing_headers,}
            )

    def check_insecure_cookies(self, actual_ip, response):
        # check cookie headers
        found_insecure_cookies = []
        for c in response.cookies:
            insecure = []
            if response.url.startswith("https:"):
                if not c.name.startswith("__Secure-") and not c.name.startswith(
                    "__Host-"
                ):
                    insecure.append("missing __Secure- or __Host-Prefix")
                if not c.secure:
                    insecure.append("missing secure attribute")
                if not c.has_nonstandard_attr("SameSite"):
                    insecure.append("missing SameSite attribute")

            if not c.has_nonstandard_attr("HttpOnly"):
                insecure.append("missing HttpOnly attribute")

            if len(insecure):
                found_insecure_cookies.append(
                    f"insecure cookie {c.name}: {', '.join(insecure)}"
                )

        if found_insecure_cookies:
            self.results["Insecure-Cookie-URLs"].append(
                {
                    "url": response.url,
                    "ip": actual_ip,
                    "errors": found_insecure_cookies,
                }
            )
