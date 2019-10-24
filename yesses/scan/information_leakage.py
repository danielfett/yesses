from typing import List
import re
import logging

from yesses.module import YModule, YExample
from yesses import utils

log = logging.getLogger('scan/information_leakage')


class InformationLeakage(YModule):
    """
    Scan HTML, JavaScript and CSS files for information leakages. This is done by search with
    regular expressions for email and ip addresses and strings that looks like paths.
    For paths there is also a list of common directories to determine whether a path
    is a real path or not. Furthermore there is a list with common file endings to check
    if a path ends with a file name or a string is a file name. All the regex expressions
    are searching only for strings which are either at the beginning or end of a line or
    which have a whitespace before or after.
    """

    REGEX_IDENTIFIER = ["email", "ip", "path", "file"]
    REGEX = [r"(^|\s)[a-zA-Z0-9-._]+@[a-zA-Z0-9-_]+\.[a-zA-Z0-9-]+(\s|$)",
             r"(^|\s)([0-9]{1,3}\.){3}[0-9]{1,3}(\s|$)",
             r"(^|\s)/([a-zA-Z0-9-_.]+/)*[a-zA-Z0-9-_.]+/?(\s|$)",
             r"(^|\s)/?[a-zA-Z0-9-_]+\.[a-zA-Z0-9]+(\s|$)"]

    DIR_LIST = "assets/information_leakage/common-directories.txt"
    FILE_ENDINGS_LIST = "assets/information_leakage/common-file-endings.txt"

    INPUTS = {
        "pages": {
            "required_keys": [
                "url",
                "data"
            ],
            "description": "Required. Pages to search for information leakage",
        },
        "dir_list": {
            "required_keys": None,
            "description": "List with common directories to determine whether a string is a path",
            "default": DIR_LIST,
        },
        "file_ending_list": {
            "required_keys": None,
            "description": "List with common file endings to determine whether a string is a file name",
            "default": FILE_ENDINGS_LIST,
        },
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

    EXAMPLES = [
        YExample("Check example strings for information leakage", """
      - scan Information Leakage:
          pages: 
            - url: page0
              data: "\n\n test@example.com \n\n192.168.2.123test\n\n"
            - url: page1
              data: "/1x23/ex234\n\n /var/www/html \n\n /home/user/.profile\n\n /docs/"
            - url: page2
              data: "\n\n 192.168.2.12 /usr/share/docs/ajdlkf/adjfl \n\n secret.txt"
        find:
          - Leakages
    """)
    ]

    def run(self):
        dir_list = utils.read_file(self.dir_list)

        if not dir_list:
            log.error("Could not open dir list")
            return

        file_endings_list = utils.read_file(self.file_ending_list)

        if not file_endings_list:
            log.error("Could not open file endings list")
            return

        for page in self.pages:
            lines = page['data'].split('\n')
            for i, line in enumerate(lines):
                for j, regex in enumerate(self.REGEX):
                    matches = re.finditer(regex, line)
                    for match in matches:
                        if (j != 2 and j != 3) or self.check_file_or_path(match.group(0), dir_list, file_endings_list):
                            log.debug(
                                f"URL: {page['url']} Line: {i} Finding: {self.REGEX_IDENTIFIER[j]} => {match.group(0)}")
                            self.results['Leakages'].append(
                                {'url': page['url'], 'line': i, 'type': self.REGEX_IDENTIFIER[j],
                                 'finding': match.group(0)})

    def check_file_or_path(self, potential_path: str, dir_list: List[str], file_endings_list: List[str]) -> bool:
        if potential_path.split('.')[-1] in file_endings_list:
            return True

        i = 0
        split = potential_path.split('/')
        split = [s for s in split if s]
        for part in split:
            if part in dir_list:
                i += 1

        if i / len(split) >= 0.5:
            return True
        return False


if __name__ == "__main__":
    InformationLeakage.selftest()
