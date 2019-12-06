import requests
import logging
from random import randint

from yesses.module import YModule, YExample
from yesses import utils

log = logging.getLogger('discover/error_paths')


class ErrorPaths(YModule):
    """
    This module tries to provoke errors and saves the error pages in an array.
    The error pages can then be used as the inputs for the information leakage
    module and the header leakage module to search them for too much information.
    Currently, this module only calls a non-existing page to
    get a 404 not found error page.
    """
    USER_AGENTS_LIST = "assets/user-agents.txt"

    INPUTS = {
        "origins": {
            "required_keys": [
                "ip",
                "domain",
                "url"
            ],
            "description": "Required. Origins to get error pages",
        },
    }

    OUTPUTS = {
        "Error-Pages": {
            "provided_keys": [
                "url",
                "header",
                "data"
            ],
            "description": "Error pages and the content from the page"
        }
    }

    def run(self):
        # read user agents list
        user_agents = utils.read_file(self.USER_AGENTS_LIST)

        if not user_agents:
            log.error("Could not open user agent list")
            return

        for origin in self.origins:
            with utils.force_ip_connection(origin['domain'], origin['ip']):
                parsed_url = utils.UrlParser(origin['url'])

                with requests.Session() as req_sess:
                    # get page with 404 not found error
                    r = req_sess.get(
                        f"{parsed_url.origin}/yesses-scanner-nonexisting-url/opdvsltqfnlcelh/ddsleo/glcgrfmr.html",
                        headers={'User-Agent': user_agents[randint(0, len(user_agents) - 1)]})
                    parsed_url = utils.UrlParser(r.url)

                    header_list = utils.convert_header(r)
                    self.results['Error-Pages'].append(
                        {'url': parsed_url.full_url(), 'header': header_list, 'data': r.text})
