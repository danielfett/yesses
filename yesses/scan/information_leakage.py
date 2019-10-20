import re
import logging

from yesses.module import YModule

log = logging.getLogger('scan/information_leakage')


class InformationLeakage(YModule):
    """
    Scan HTML, JavaScript and CSS files for information leakages. This is done by search with
    regular expressions for email and ip addresses and strings that looks like paths.
    """

    REGEX_IDENTIFIER = ["email", "ip", "path"]
    REGEX = ["(^|\s)[a-zA-Z0-9-._]+@[a-zA-Z0-9-_]+\.[a-zA-Z0-9-]+(\s|$)",
             "(^|\s)([0-9]{1,3}\.){3}[0-9]{1,3}(\s|$)",
             "(^|\s)(/([a-zA-Z0-9-_.]+/)[a-zA-Z0-9-_.]*|/?([a-zA-Z0-9-_.]+/)[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+)(\s|$)"]

    INPUTS = {
        "pages": {
            "required_keys": [
                "url",
                "data"
            ],
            "description": "Required. Pages to search for information leakage",
        }
    }

    OUTPUTS = {
        "Leakages": {
            "provided_keys": [
                "url",
                "line",
                "type",
                "finding"
            ],
            "description": "Potential information leakages"
        }
    }

    def run(self):
        for page in self.pages:
            split = page['data'].split('\n')
            for i, line in enumerate(split):
                for j, regex in enumerate(self.REGEX):
                    matches = re.finditer(regex, line)
                    for match in matches:
                        log.debug(f"URL: {page['url']} Line: {i} Finding: {self.REGEX_IDENTIFIER[j]} => {match.group(0)}")
                        self.results['Leakages'].append(
                            {'url': page['url'], 'line': i, 'type': self.REGEX_IDENTIFIER[j],
                             'finding': match.group(0)})

        print(self.results['Leakages'])


if __name__ == "__main__":
    i = InformationLeakage()
    i.run()
