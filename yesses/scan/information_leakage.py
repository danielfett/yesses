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

    REGEX = {"email": r"(^|\s|\()[a-zA-Z0-9-._]+@[a-zA-Z0-9-_]+\.[a-zA-Z0-9-]+(\s|$|\))",
             "ip": r"([0-9]{1,3}\.){3}[0-9]{1,3}",
             "path": r"(^|\s|\()/?([a-zA-Z0-9-_.]+/)+[a-zA-Z0-9-_.]+/?(\s|$|\))",
             "file": r"(^|\s|\()/?[a-zA-Z0-9-_]+\.[a-zA-Z0-9]+(\s|$|\))",
             "server-info": r"(^|\s|\()[a-zA-Z_-]{3,}/[0-9\.]+(\s\([a-zA-Z_-]+\))?(\s|$|\))",
             "version-info": r"(^|\s|\()[a-zA-Z0-9-_.]*[Vv]ersion:?\s([0-9]+\.)+[0-9]+(\s|$|\))"}

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
        "search_regex": {
            "required_keys": [
                "type",
                "regex"
            ],
            "description": "Own regular expression to search in pages (will be added to the existing ones)",
            "default": {}
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
              data: "<!-- test@example.com /var/home/bla aaa --><html>\n\n<head><script src='ajkldfjalk'></script></head>\n\n <body>\n\n<!-- This is a comment --><h1>Title</h1>\n\n<!-- secret.txt \n\n/1x23/ex234--><p>Text with path /home/user/secret/key.pub</p> <a href='/docs/'>Website</a> <label>192.168.2.196 /usr/share/docs/ajdlkf/adjfl</label>\n\n<style> test@example.com </style>\n\n</body>"
            - url: page1
              data: "<html><script>// This is a js comment192.256.170.128\n\nfunction {return 'Hello World';}\n\n</script><body><p>bla Gitea Version: 1.11.0+dev-180-gd5b1e6bc5</p></body><script>// Comment two with email@example.com \n\n console.log('test')/* Comment over\n\n several lines\n\n*/</script></html>\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
            - url: page2
              data: "/*! modernizr 3.6.0 (Custom Build) | MIT *\n\n* https://modernizr.com/download/?-svgclippaths-setclasses !*/ \n\n!function(e,n,s){function o(e) // Comment three\n\n{var n=f.className,s=Modernizr._con /* Last \n\n multi \n\n line \n\n comment */ flakjdlfjldjfl\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
          search_regex:
            - type: new_regex
              regex: (^|\s)a{3}(\s|$)
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

        # add custom regular expressions if there are any
        for sr in self.search_regex:
            self.REGEX[sr['type']] = sr['regex']

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
        if not html:
            return

        for script in sess.soup(["script", "style"]):
            script.extract()
        text = sess.soup.get_text()
        self.search_string(text, "visible_text", ["email"], sess)

    def check_html_comments(self, sess: InformationLeakageSession):
        html = sess.soup.find_all('html')
        if not html:
            return

        for script in sess.soup(["script", "style"]):
            script.extract()
        self.search_comments(sess.soup.prettify(), "html_comment", "text/html", sess)

    def check_js_css_comments(self, sess: InformationLeakageSession):
        html = sess.soup.find_all('html')
        # if there is no html tag then it is most likely a css or js file
        if not html:
            self.search_comments(sess.page['data'], "css_js_comment", "application/javascript", sess)
        else:
            # If there is an html tag then extract the script and style tags
            # and search them.
            for script in sess.soup(["script", "style"]):
                self.search_comments(script.text, "css_js_comment", "application/javascript", sess)

    def search_comments(self, text: str, type: str, mime: str, sess: InformationLeakageSession):
        comments = comment_parser.extract_comments_from_str(text, mime)
        for comment in comments:
            self.search_string(comment._text, type, [], sess)

    def search_string(self, text: str, found: str, no_search: List[str], sess: InformationLeakageSession):
        for type, regex in self.REGEX.items():
            if type in no_search:
                continue
            matches = re.finditer(regex, text)
            for match in matches:
                finding = match.group(0).strip()
                if (type == 'path' or type == 'file') and not self.check_file_or_path(finding, sess.dir_list,
                                                                                      sess.file_endings_list):
                    continue
                elif type == 'ip' and not self.check_ip_address(finding):
                    continue
                log.debug(
                    f"URL: {sess.page['url']} Found: {found} Finding: {type} => {finding}")
                self.results['Leakages'].append(
                    {'url': sess.page['url'], 'type': type, 'found': found, 'finding': finding})

    @staticmethod
    def check_file_or_path(potential_path: str, dir_list: List[str], file_endings_list: List[str]) -> bool:
        if potential_path.split('.')[-1] in file_endings_list:
            return True

        i = 0
        split = potential_path.split('/')
        split = [s for s in split if s]

        if len(split) > 3:
            return True

        for part in split:
            if part in dir_list:
                i += 1

        if i / len(split) >= 0.5:
            return True
        return False

    @staticmethod
    def check_ip_address(ip: str) -> bool:
        splits = ip.split('.')
        for split in splits:
            if int(split) > 255:
                return False
        return True


if __name__ == "__main__":
    InformationLeakage.selftest()
