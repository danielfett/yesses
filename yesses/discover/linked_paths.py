import logging
import requests
from bs4 import BeautifulSoup
import re
import time
import threading

from yesses.module import YModule
from yesses.utils import force_ip_connection, eliminate_duplicated_origins, UrlParser

logging.getLogger("requests").setLevel(logging.ERROR)
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("chardet").setLevel(logging.ERROR)
log = logging.getLogger('discover/linked_paths')


class LinkedPaths(YModule):
    """
    This module takes urls and collects recursively all links, which are local
    to this url.
    """

    THREADS = 40

    USER_AGENTS = [
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:69.0) Gecko/20100101 Firefox/69.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18362"]

    # TODO: replace with randomint
    RANDOM = [3, 0, 4, 0, 2, 2, 0, 3, 3, 1, 3, 4, 3, 3, 0, 1, 0, 3, 0, 4, 1, 1, 4, 1, 2, 0, 3, 1, 3, 0, 1, 0, 4, 1, 0,
              2, 4, 1, 4, 3, 0, 1, 3, 4, 1, 3, 3, 2, 1, 4, 2, 4, 1, 4, 1, 3, 0, 2, 1, 3, 1, 2, 0, 2, 2, 4, 1, 4, 3, 2,
              4, 3, 4, 0, 0, 2, 4, 2, 4, 0]

    INPUTS = {
        "origins": {
            "required_keys": [
                "ip",
                "domain",
                "url"
            ],
            "description": "Required. Origins to scan for leaky paths",
        },
        "threads": {
            "required_keys": None,
            "description": "Number of threads to run search in parallel",
            "default": THREADS,
        }
    }

    OUTPUTS = {
        "Linked-Paths": {
            "provided_keys": [
                "url"
            ],
            "description": "List of all linked pages from the url"
        },
        "Linked-Pages": {
            "provided_keys": [
                "url",
                "data"
            ],
            "description": "Pages and the content from the page"
        }
    }

    # TODO refactor to eliminate the init
    def init(self, url: str):
        self.url = url
        self.urls_visited = []
        self.parsed_url = UrlParser(url)
        # save expression: |mailto:|tel:|skype:|news:
        self.regular_exp = re.compile(
            f"^https?://([a-zA-Z0-9_.-]*\.|){re.escape(self.parsed_url.base_domain)}|"
            f"^(?![a-zA-Z-]+:|//|#|[\n]|/$|$)")
        self.random_state = 0 # TODO replace with randomint

    def run(self):
        # delete duplicated origins (same domain can have a IPv4 and IPv6 address)
        filtered_origins = eliminate_duplicated_origins(self.origins)

        for origin in filtered_origins.values():
            with force_ip_connection(origin['domain'], origin['ip']):
                self.init(origin['url'])
                start = time.time()
                req_sess = requests.Session()
                # TODO pass all parameters and pack them into an object
                self.scrap_urls(self.parsed_url, req_sess, 0)
                log.debug(f"Scraped site in {time.time() - start}s")

    def scrap_urls(self, parsed_url: UrlParser, req_sess: requests.Session, level: int):
        # get new page
        r = req_sess.get(parsed_url.full_url(),
                         headers={'User-Agent': self.USER_AGENTS[self.RANDOM[self.random_state]]})
        self.random_state = (self.random_state + 1) % len(self.RANDOM)
        # parse url returned by requests in the case we have been redirected
        forwarded_parsed_url = UrlParser(r.url)

        # Add the url to the visited urls if it doesn't return a error and if it's
        # not in the already visited urls. We have to check this again because
        # we could have been redirected to a page we have already visited.
        # We also have to check again if it's a local page because we could
        # have been redirected to another website.
        if r.status_code == 200 and forwarded_parsed_url not in self.urls_visited \
                and re.match(self.regular_exp, forwarded_parsed_url.full_url()):
            self.urls_visited.append(forwarded_parsed_url)
            self.results['Linked-Paths'].append({'url': forwarded_parsed_url.full_url()})
            self.results['Linked-Pages'].append({'url': forwarded_parsed_url.full_url(), 'data': r.text})
        else:
            return

        log.debug(forwarded_parsed_url)

        # check if this page is parsable by beautiful soup
        if forwarded_parsed_url.file_ending.lower() not in ['', '.html', '.htm', '.php', '.cgi']:
            return

        soup = BeautifulSoup(r.text, "lxml")

        # get all linked pages and css files
        links = [link.get('href') for link in
                 soup.findAll(['a', 'link'], attrs={'href': self.regular_exp})]  # type: List[str]
        # get all JavaScript files
        links += [script.get('src') for script in soup.findAll('script', attrs={'src': self.regular_exp})]

        if level == 0:
            # open new thread for every link on the front page
            length = max(int(len(links) / self.threads), 1)
            ths = []
            for i in range(0, len(links), length):
                req_sess = requests.Session()
                th = threading.Thread(target=self.process_links,
                                      args=(links[i:i + length], forwarded_parsed_url, req_sess, level,))
                th.start()
                ths.append(th)

            for th in ths:
                th.join()
        else:
            # iterate over all files and parse them recursively
            self.process_links(links, forwarded_parsed_url, req_sess, level)

    def process_links(self, links: list, forwarded_parsed_url: UrlParser, req_sess: requests.Session, level: int):
        for link in links:
            parsed_link = UrlParser(link)
            if parsed_link.netloc == '':
                parsed_link.url_without_path = forwarded_parsed_url.url_without_path
                parsed_link.path = self.join_paths(forwarded_parsed_url.path, parsed_link.path)

            if parsed_link not in self.urls_visited:
                self.scrap_urls(parsed_link, req_sess, level + 1)

    @staticmethod
    def join_paths(path_prefix: str, path: str) -> str:
        """
        Method determines whether the path is absolute or not and
        if it is not absolute it concatenates the relative path
        with its prefix.
        :param path_prefix:
        :param path:
        :return: new absolute path
        """
        if path.startswith('/'):
            return path
        elif re.match("^/.+/$", path_prefix):
            return f"{path_prefix}{path}"
        else:
            return f"/{path}"
