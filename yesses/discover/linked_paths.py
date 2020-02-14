from typing import Dict, List
import logging
import requests
from bs4 import BeautifulSoup
import re
import time
import threading
from random import randint
import queue

from yesses.module import YModule
from yesses import utils

logging.getLogger("requests").setLevel(logging.ERROR)
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("chardet").setLevel(logging.ERROR)
log = logging.getLogger("discover/linked_paths")


class LinkedPathsSession(utils.ConcurrentSession):
    def __init__(self, origin: Dict, threads: int):
        super().__init__(threads)
        start_parsed_url = utils.UrlParser(origin["url"])
        self.task_queue = queue.Queue()  # type: queue.Queue[utils.UrlParser]
        self.task_queue.put(start_parsed_url)
        self.regex = re.compile(
            rf"^https?://([a-zA-Z0-9_.-]*\.|){re.escape(start_parsed_url.base_domain)}|"
            rf"^(?![a-zA-Z-]+:|//|#|[\n]|/$|$)"
        )
        self.urls_visited = []  # type: List[utils.UrlParser]


class LinkedPaths(YModule):
    """This module takes URLs and collects recursively all links, which
    are local to this URL.

    """

    THREADS = 40
    RECURSION_DEPTH = 5

    USER_AGENTS_LIST = "assets/user-agents.txt"

    INPUTS = {
        "origins": {
            "required_keys": ["ip", "domain", "url"],
            "description": "Required. Origins to scan for leaky paths",
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
        },
    }

    OUTPUTS = {
        "Linked-Paths": {
            "provided_keys": ["url"],
            "description": "List of all linked pages from the url",
        },
        "Linked-Pages": {
            "provided_keys": ["url", "header", "data"],
            "description": "Pages and the content from the page",
        },
    }

    def run(self):
        # read user agents list
        self.user_agents = utils.read_file(self.USER_AGENTS_LIST)

        if not self.user_agents:
            log.error("Could not open user agent list")
            return

        filtered_origins = utils.filter_origins(self.origins)

        for origin in filtered_origins.values():
            with utils.force_ip_connection(origin["domain"], origin["ip"]):
                start = time.time()
                sess = LinkedPathsSession(origin, self.threads)

                ths = []
                for i in range(self.threads):
                    th = threading.Thread(target=self.worker, args=(sess,))
                    th.start()
                    ths.append(th)

                for th in ths:
                    th.join()

                log.debug(f"Scraped site in {time.time() - start}s")

    def worker(self, sess: LinkedPathsSession):
        with requests.Session() as req_sess:
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

                self.scrape_urls(task, req_sess, sess)

    def scrape_urls(
        self,
        parsed_url: utils.UrlParser,
        req_sess: requests.Session,
        sess: LinkedPathsSession,
    ):
        # get new page
        r = req_sess.get(
            parsed_url.full_url(),
            headers={
                "User-Agent": self.user_agents[randint(0, len(self.user_agents) - 1)]
            },
        )
        # parse url returned by requests in the case we have been redirected
        forwarded_parsed_url = utils.UrlParser(r.url)

        # Add the url if it's not in the already visited urls. We have to check
        # this again because we could have been redirected to a page we have
        # already visited. We also have to check again if it's a local page
        # because we could have been redirected to another website.
        if forwarded_parsed_url not in sess.urls_visited and re.match(
            sess.regex, forwarded_parsed_url.full_url()
        ):
            sess.urls_visited.append(forwarded_parsed_url)
            self.results["Linked-Paths"].append(
                {"url": forwarded_parsed_url.full_url()}
            )
            header_list = utils.convert_header(r)
            self.results["Linked-Pages"].append(
                {
                    "url": forwarded_parsed_url.full_url(),
                    "header": header_list,
                    "data": r.text,
                }
            )
        else:
            return

        log.debug(forwarded_parsed_url)

        # check if this page is parsable by beautiful soup
        if not utils.request_is_text(r):
            return

        soup = BeautifulSoup(r.text, "lxml")

        # get all linked pages and css files
        links = [
            link.get("href")
            for link in soup.findAll(["a", "link"], attrs={"href": sess.regex})
        ]  # type: List[str]
        # get all JavaScript files
        links += [
            script.get("src")
            for script in soup.findAll("script", attrs={"src": sess.regex})
        ]

        for link in links:
            parsed_link = utils.UrlParser(link)
            if parsed_link.netloc == "":
                parsed_link.origin = forwarded_parsed_url.origin
                parsed_link.path = self.join_paths(
                    forwarded_parsed_url.path, parsed_link.path
                )

            if (
                parsed_link not in sess.urls_visited
                and parsed_link.file_ending not in [".png", ".jpg", ".jpeg", ".pdf"]
                and parsed_link.path_depth <= self.recursion_depth
            ):
                sess.task_queue.put(parsed_link)

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
        if path.startswith("/"):
            return path
        elif re.match("^/.+/$", path_prefix):
            return f"{path_prefix}{path}"
        else:
            return f"/{path}"
