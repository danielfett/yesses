import re
import logging

from yesses.module import YModule, YExample

log = logging.getLogger("scan/header_leakage")


class HeaderLeakage(YModule):
    """This module searches for potentially sensitive much information in
HTTP headers. It checks if the 'Server' attribute contains too much
information and if the 'X-Powered-By' and/or the 'X-AspNet-Version'
attribute is set.

    """

    INPUTS = {
        "pages": {
            "required_keys": ["url", "header"],
            "description": "Required. Urls with headers to search for information leakage",
        },
    }

    OUTPUTS = {
        "Leakages": {
            "provided_keys": ["url", "header"],
            "description": "Potential information leakages",
        }
    }

    def run(self):
        for page in self.pages:
            for header_attr in page["header"]:
                if re.match("^server: [a-zA-Z_-]+/.*", header_attr, re.IGNORECASE):
                    log.debug(f"Found potential leakage: {header_attr}")
                    self.results["Leakages"].append(
                        {"url": page["url"], "header": header_attr}
                    )
                if re.match(r"x-powered-by: .*", header_attr, re.IGNORECASE):
                    log.debug(f"Found potential leakage: {header_attr}")
                    self.results["Leakages"].append(
                        {"url": page["url"], "header": header_attr}
                    )
                if re.match(r"x-aspnet-version: .*", header_attr, re.IGNORECASE):
                    log.debug(f"Found potential leakage: {header_attr}")
                    self.results["Leakages"].append(
                        {"url": page["url"], "header": header_attr}
                    )
