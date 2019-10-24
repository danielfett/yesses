from typing import List
import logging
import requests
import threading
from random import randint
import queue
import math

from yesses.module import YModule
from yesses import utils

logging.getLogger("requests").setLevel(logging.ERROR)
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("chardet").setLevel(logging.ERROR)
log = logging.getLogger('discover/hidden_paths')


class HiddenPathsSession(utils.ConcurrentSession):

    def __init__(self, task_queue: queue.Queue, dir_list: List, threads: int):
        super().__init__(threads)
        self.task_queue = task_queue
        self.dir_list = dir_list  # type: List[str]
        self.pages_found = []  # type: List[utils.UrlParser]


class HiddenPaths(YModule):
    """
    This module takes urls and linked paths from the Linked Paths module.
    It extracts potential folders from the linked paths and searches in
    this folders with a wordlist for potential hidden files.
    """

    THREADS = 10
    RECURSION_DEPTH = 3
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
        "recursion_depth": {
            "required_keys": None,
            "description": "Max depth to search for hidden files and directories. "
                           "Found files can only have recursion_depth + 1 depth",
            "default": RECURSION_DEPTH,
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
        },
        "Directories": {
            "provided_keys": [
                "url"
            ],
            "description": "Directories found on the web servers"
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
        filtered_origins = utils.eliminate_duplicated_origins(self.origins)

        for origin in filtered_origins.values():
            with utils.force_ip_connection(origin['domain'], origin['ip']):
                parsed_url = utils.UrlParser(origin['url'])

                # fill task queue with existing directories if there are any
                dirs = self.potential_dirs[parsed_url.url_without_path]
                task_queue = queue.Queue()

                for dir in dirs:
                    for i in range(self.threads):
                        task_queue.put((dir, i))

                ths = []
                sess = HiddenPathsSession(task_queue, dir_list, self.threads)
                for i in range(self.threads):
                    th = threading.Thread(target=self.worker,
                                          args=(sess,))
                    th.start()
                    ths.append(th)

                for th in ths:
                    th.join()

    def worker(self, sess: HiddenPathsSession):
        req_sess = requests.Session()
        sess.register_thread(threading.current_thread().ident)
        self_finished = False
        while not sess.is_ready():
            try:
                task = sess.task_queue.get(block=True, timeout=0.3)
                if self_finished:
                    sess.unready(threading.current_thread().ident)
                self_finished = False
            except queue.Empty:
                self_finished = True
                sess.ready(threading.current_thread().ident)
                continue

            url, i = task
            length = max(math.ceil(len(sess.dir_list) / self.threads), 1)
            for dir in sess.dir_list[i * length:(i + 1) * length]:
                tmp_url = f"{url}{dir}"
                r = req_sess.get(tmp_url, headers={'User-Agent': self.USER_AGENTS[randint(0, 4)]})
                parsed_url = utils.UrlParser(r.url)
                if r.status_code == 200 and parsed_url.full_url() not in self.linked_urls and \
                        not ('index' in dir and url in self.linked_urls) and parsed_url not in sess.pages_found:
                    self.results['Hidden-Paths'].append({'url': parsed_url.full_url()})
                    sess.pages_found.append(parsed_url)
                    log.debug(f"Hidden page found: {parsed_url.full_url()}")
                    if utils.request_is_text(r):
                        self.results['Hidden-Pages'].append({'url': parsed_url.full_url(), 'data': r.text})
                elif (r.status_code == 403 or r.status_code == 200) \
                        and parsed_url.path.endswith('/') and parsed_url not in sess.pages_found:
                    log.debug(f"Directory found: {parsed_url.full_url()}")
                    sess.pages_found.append(parsed_url)
                    self.results['Directories'].append({'url': parsed_url.full_url()})
                    if parsed_url.path_depth <= self.recursion_depth:
                        for i in range(self.threads):
                            sess.task_queue.put((parsed_url.full_url(), i))

    def get_potential_dirs(self):
        self.potential_dirs = {}

        for origin in self.origins:
            parsed_url = utils.UrlParser(origin['url'])
            tmp = f"{parsed_url.url_without_path}/"
            self.potential_dirs[parsed_url.url_without_path] = [tmp]

        for urld in self.linked_paths:
            url = urld['url']
            parsed_url = utils.UrlParser(url)
            if parsed_url.url_without_path not in self.potential_dirs:
                tmp = f"{parsed_url.url_without_path}/"
                self.potential_dirs[parsed_url.url_without_path] = [tmp]
            split = parsed_url.path.split('/')
            tmp = f"{parsed_url.url_without_path}/"
            for i in range(1, len(split) - 1):
                tmp = f"{tmp}{split[i]}/"
                if tmp not in self.potential_dirs[parsed_url.url_without_path]:
                    self.potential_dirs[parsed_url.url_without_path].append(tmp)
