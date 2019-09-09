import re

from urllib3.util import connection
from contextlib import contextmanager
_orig_create_connection = connection.create_connection

@contextmanager
def force_ip_connection(domain, ip):
    def patched_create_connection(address, *args, **kwargs):
        """Wrap urllib3's create_connection to resolve the name elsewhere"""
        # resolve hostname to an ip address; use your own
        # resolver here, as otherwise the system resolver will be used.
        host, port = address
        if host == domain:
            hostname = ip
        else:
            hostname = host
        return _orig_create_connection((hostname, port), *args, **kwargs)

    connection.create_connection = patched_create_connection
    yield
    connection.create_connection = _orig_create_connection

def clean_expression(expr):
    return re.sub(r'''\s+''', ' ', expr).strip()
