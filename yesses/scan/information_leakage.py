from typing import List
import re
import logging
from bs4 import BeautifulSoup
from comment_parser import comment_parser

from yesses.module import YModule, YExample
from yesses import utils

log = logging.getLogger('scan/information_leakage')


class InformationLeakageSession:

    def __init__(self, soup: BeautifulSoup, page, dir_list: List[str], file_endings_list: List[str]):
        self.soup = soup
        self.page = page
        self.dir_list = dir_list
        self.file_endings_list = file_endings_list


class InformationLeakage(YModule):
    """
    Scan HTML, JavaScript and CSS files for information leakages. This is done by search with
    regular expressions for email and ip addresses and strings that looks like paths in the
    visible text of a HTML side or in HTML, JavaScript and CSS comments.
    For paths there is also a list of common directories to determine whether a path
    is a real path or not. Furthermore there is a list with common file endings to check
    if a path ends with a file name or a string is a file name. All the regex expressions
    are searching only for strings which are either at the beginning or end of a line or
    which have a whitespace before or after.
    """

    REGEX_IDENTIFIER = ["email", "ip", "path", "file", "server-info"]
    REGEX = [r"(^|\s)[a-zA-Z0-9-._]+@[a-zA-Z0-9-_]+\.[a-zA-Z0-9-]+(\s|$)",
             r"(^|\s)([0-9]{1,3}\.){3}[0-9]{1,3}(\s|$)",
             r"(^|\s)/([a-zA-Z0-9-_.]+/)*[a-zA-Z0-9-_.]+/?(\s|$)",
             r"(^|\s)/?[a-zA-Z0-9-_]+\.[a-zA-Z0-9]+(\s|$)",
             r"(^|\s)[a-zA-Z_-]+/[0-9\.]+(\s\([a-zA-Z_-]+\))?(\s|$)"]

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
                "type",
                "found",
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
              data: "<!-- test@example.com /var/home/bla --><html>\n\n<head><script src='ajkldfjalk'></script></head>\n\n <body>\n\n<!-- This is a comment --><h1>Title</h1>\n\n<!-- secret.txt \n\n/1x23/ex234--><p>Text with path /home/user/secret/key.pub</p> <a href='/docs/'>Website</a> <label>192.168.2.196 /usr/share/docs/ajdlkf/adjfl</label>\n\n<style> test@example.com </style>\n\n</body>"
            - url: page1
              data: "<html><script>// This is a js comment 192.168.170.128\n\nfunction {return 'Hello World';}\n\n</script><body></body><script>// Comment two with email@example.com \n\n console.log('test')/* Comment over\n\n several lines\n\n*/</script></html>\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
            - url: page2
              data: "/*! modernizr 3.6.0 (Custom Build) | MIT *\n\n* https://modernizr.com/download/?-svgclippaths-setclasses !*/ \n\n!function(e,n,s){function o(e) // Comment three\n\n{var n=f.className,s=Modernizr._con /* Last \n\n multi \n\n line \n\n comment */ flakjdlfjldjfl\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
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
            soup = BeautifulSoup(page['data'], 'html.parser')

            sess = InformationLeakageSession(soup, page, dir_list, file_endings_list)

            # search in CSS or JavaScript comments for information leakage
            self.check_js_css_comments(sess)

            # search in the visible text for information leakages
            self.check_visible_text(sess)

            # search in comments for information leakages
            self.check_html_comments(sess)

    def check_visible_text(self, sess: InformationLeakageSession):
        html = sess.soup.find_all('html')
        if html:
            for script in sess.soup(["script", "style"]):
                script.extract()
            text = sess.soup.get_text()
            self.search_string(text, "visible_text", [1, 2, 3, 4], sess)

    def check_html_comments(self, sess: InformationLeakageSession):
        # If there aren't many lines it is likely that we deal with a minified
        # js or css document. There shouldn't be any comments left and '//' in URLs
        # will be interpreted as comments which is wrong.
        if sess.page['data'].count('\n') <= 10:
            return

        comments = comment_parser.extract_comments_from_str(sess.page['data'], "text/html")
        for comment in comments:
            self.search_string(comment._text, "html_comment", list(range(5)), sess)

    def check_js_css_comments(self, sess: InformationLeakageSession):
        # If there aren't many lines it is likely that we deal with a minified
        # js or css document. There shouldn't be any comments left and '//' in URLs
        # will be interpreted as comments which is wrong.
        if sess.page['data'].count('\n') <= 10:
            return

        comments = comment_parser.extract_comments_from_str(sess.page['data'], "application/javascript")
        for comment in comments:
            self.search_string(comment._text, "css_js_comment", list(range(5)), sess)

    def search_string(self, text: str, found: str, regex_list: List[int], sess: InformationLeakageSession):
        for j in regex_list:
            matches = re.finditer(self.REGEX[j], text)
            for match in matches:
                finding = match.group(0).strip()
                if (j != 2 and j != 3) or self.check_file_or_path(finding, sess.dir_list,
                                                                  sess.file_endings_list):
                    log.debug(
                        f"URL: {sess.page['url']} Found: {found} Finding: {self.REGEX_IDENTIFIER[j]} => {finding}")
                    self.results['Leakages'].append(
                        {'url': sess.page['url'], 'type': self.REGEX_IDENTIFIER[j],
                         'found': found, 'finding': finding})

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
