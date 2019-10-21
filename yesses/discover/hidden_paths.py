import logging
import requests
import threading

from yesses.module import YModule
from yesses.utils import force_ip_connection, eliminate_duplicated_origins, UrlParser

logging.getLogger("requests").setLevel(logging.ERROR)
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("chardet").setLevel(logging.ERROR)
log = logging.getLogger('discover/hidden_paths')


class HiddenPaths(YModule):
    """
    This module takes urls and linked paths from the Linked Paths module.
    It extracts potential folders from the linked paths and searches in
    this folders with a wordlist for potential hidden files.
    """

    THREADS = 4
    PATH_LIST = "assets/hidden_paths_lists/apache.lst"

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
        "linked_paths": {
            "required_keys": [
                "url"
            ],
            "description": "Required. Origins to scan for leaky paths",
        },
        "list": {
            "required_keys": None,
            "description": "List to scan for leaky paths",
            "default": PATH_LIST,
        },
        "threads": {
            "required_keys": None,
            "description": "Number of threads to run search in parallel",
            "default": THREADS,
        }
    }

    OUTPUTS = {
        "Hidden-Paths": {
            "provided_keys": [
                "url",
            ],
            "description": "All hidden paths"
        },
        "Hidden-Pages": {
            "provided_keys": [
                "url",
                "data"
            ],
            "description": "Pages and the content from the page"
        }
    }

    def init(self):
        self.random_state = 0

    def run(self):
        self.init()

        with open(self.list) as file:
            lines = file.readlines()
            lines = [line.strip('\n') for line in lines]

        if not lines:
            log.error("Could not open path list")
            return

        # find potential directories from linked urls
        self.get_potential_dirs()
        self.linked_urls = [item['url'] for item in self.linked_paths]
        print(self.potential_dirs)

        # delete duplicated origins (same domain can have a IPv4 and IPv6 address)
        filtered_origins = eliminate_duplicated_origins(self.origins)

        for origin in filtered_origins.values():
            parsed_url = UrlParser(origin['url'])
            with force_ip_connection(origin['domain'], origin['ip']):

                dirs = self.potential_dirs[parsed_url.url_without_path]

                length = max(int(len(dirs) / self.threads), 1)
                ths = []
                for i in range(0, len(dirs), length):
                    req_sess = requests.Session()
                    th = threading.Thread(target=self.check_dirs,
                                          args=(parsed_url.url_without_path, dirs[i:i + length], lines, req_sess,))
                    th.start()
                    ths.append(th)

                for th in ths:
                    th.join()

    def check_dirs(self, url: str, starts: [list], dirs: [list], req_sess: requests.Session):
        for start in starts:
            self.check_dir(url, start, dirs, req_sess)

    def check_dir(self, url: str, start: str, dirs: [list], req_sess: requests.Session):
        for dir in [''] + dirs:
            if not dir.startswith('#'):
                tmp_url = f"{url}{start}{dir}"
                r = req_sess.get(tmp_url,
                                 headers={'User-Agent': self.USER_AGENTS[self.RANDOM[self.random_state]]})
                self.random_state = (self.random_state + 1) % len(self.RANDOM)
                if r.status_code == 200 and tmp_url not in self.linked_urls and \
                        not ('index' in dir and f"{url}{start}" in self.linked_urls):
                    self.results['Hidden-Paths'].append({'url': tmp_url})
                    if 'text' in r.headers['content-type']:
                        self.results['Hidden-Pages'].append({'url': tmp_url, 'data': r.text})
                    log.debug(tmp_url)

    def get_potential_dirs(self):
        self.potential_dirs = {}

        for urld in self.linked_paths:
            url = urld['url']
            parsed_url = UrlParser(url)
            if parsed_url.url_without_path not in self.potential_dirs:
                self.potential_dirs[parsed_url.url_without_path] = ['/']
            split = parsed_url.path.split('/')
            tmp = '/'
            for i in range(1, len(split) - 1):
                tmp = f"{tmp}{split[i]}/"
                if tmp not in self.potential_dirs[parsed_url.url_without_path]:
                    self.potential_dirs[parsed_url.url_without_path].append(tmp)
