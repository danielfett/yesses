import re
import logging

from yesses.module import YModule, YExample

log = logging.getLogger('scan/header_leakage')


class HeaderLeakage(YModule):
    """
    This module searches for to much information in the http header.
    It checks if the 'Server' attribute contains to much information
    and if the 'X-Powered-By' and/or the 'X-AspNet-Version' attribute
    is set.
    """
    INPUTS = {
        "pages": {
            "required_keys": [
                "url",
                "header"
            ],
            "description": "Required. Urls with headers to search for information leakage",
        },
    }

    OUTPUTS = {
        "Leakages": {
            "provided_keys": [
                "url",
                "header"
            ],
            "description": "Potential information leakages"
        }
    }

    def run(self):
        for page in self.pages:
            header = dict(page['header'])
            if "Server" in header and re.match("^[a-zA-Z_-]+/.*", header['Server']):
                log.debug(f"Found potential leakage: {header['Server']}")
                self.results['Leakages'].append({'url': page['url'], 'header': f"Server: {header['Server']}"})
            if "X-Powered-By" in header:
                log.debug(f"Found potential leakage: {header['X-Powered-By']}")
                self.results['Leakages'].append(
                    {'url': page['url'], 'header': f"X-Powered-By: {header['X-Powered-By']}"})
            if "X-AspNet-Version" in header:
                log.debug(f"Found potential leakage: {header['X-AspNet-Version']}")
                self.results['Leakages'].append(
                    {'url': page['url'], 'header': f"X-AspNet-Version: {header['X-AspNet-Version']}"})
