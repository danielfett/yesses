import logging
import requests
import threading
from random import randint
import queue
import math

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
            "description": "Existing urls to guess directories to start the search",
            "default": {}
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

    def run(self):
        with open(self.list) as file:
            dir_list = file.readlines()
            dir_list = [''] + [line.strip('\n') for line in dir_list if not line.startswith('#')]

        if not dir_list:
            log.error("Could not open path list")
            return

        # find potential directories from linked urls
        self.get_potential_dirs()
        self.linked_urls = [item['url'] for item in self.linked_paths]

        # delete duplicated origins (same domain can have a IPv4 and IPv6 address)
        filtered_origins = eliminate_duplicated_origins(self.origins)

        for origin in filtered_origins.values():
            with force_ip_connection(origin['domain'], origin['ip']):
                parsed_url = UrlParser(origin['url'])

                # fill task queue with existing directories if there are any
                dirs = self.potential_dirs[parsed_url.url_without_path]
                task_queue = queue.Queue()

                for dir in dirs:
                    for i in range(self.threads):
                        task_queue.put((dir, i))

                ths = []
                self.ready = 0
                for i in range(self.threads):
                    req_sess = requests.Session()
                    th = threading.Thread(target=self.worker,
                                          args=(task_queue, dir_list, req_sess,))
                    th.start()
                    ths.append(th)

                for th in ths:
                    th.join()

    def worker(self, task_queue: queue.Queue, dir_list: [str], req_sess: requests.Session):
        while self.ready != self.threads:
            try:
                task = task_queue.get_nowait()
                self_finised = False
            except queue.Empty:
                self_finised = True
                self.ready += 1
                continue

            if not self_finised:
                url, i = task
                length = max(math.ceil(len(dir_list) / self.threads), 1)
                for dir in dir_list[i * length:(i + 1) * length]:
                    tmp_url = f"{url}{dir}"
                    r = req_sess.get(tmp_url, headers={'User-Agent': self.USER_AGENTS[randint(0, 4)]})
                    if r.status_code == 200 and tmp_url not in self.linked_urls and \
                            not ('index' in dir and url in self.linked_urls):
                        self.results['Hidden-Paths'].append({'url': tmp_url})
                        log.debug(tmp_url)
                        if 'text' in r.headers['content-type']:
                            self.results['Hidden-Pages'].append({'url': tmp_url, 'data': r.text})

    def get_potential_dirs(self):
        self.potential_dirs = {}

        for origin in self.origins:
            parsed_url = UrlParser(origin['url'])
            tmp = f"{parsed_url.url_without_path}/"
            self.potential_dirs[parsed_url.url_without_path] = [tmp]

        for urld in self.linked_paths:
            url = urld['url']
            parsed_url = UrlParser(url)
            if parsed_url.url_without_path not in self.potential_dirs:
                tmp = f"{parsed_url.url_without_path}/"
                self.potential_dirs[parsed_url.url_without_path] = [tmp]
            split = parsed_url.path.split('/')
            tmp = f"{parsed_url.url_without_path}/"
            for i in range(1, len(split) - 1):
                tmp = f"{tmp}{split[i]}/"
                if tmp not in self.potential_dirs[parsed_url.url_without_path]:
                    self.potential_dirs[parsed_url.url_without_path].append(tmp)
