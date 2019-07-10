import re
import logging
from urllib3.util import connection
from contextlib import contextmanager
_orig_create_connection = connection.create_connection

log = logging.getLogger('utils/expect')



def expect(results, previous_results, *rules):
    log.debug(f"Current results: {results!r}")
    for rule in rules:
        rule = re.sub(r'''\s+''', ' ', rule).strip()
        for handle_fn, regex in expect_regexes:
            matches = re.match(regex, rule)
            if matches is not None:
                handle_fn(rule, matches, results, previous_results)
                break
        else:
            raise Exception(f"Illegal rule: {rule} (does not match any expect rule format)")


def expect_rule_unary(rule, matches, results, previous_results):
    inverse = matches.group('no')
    diff = matches.group("diff")
    if diff in ('some', '', None):
        diff = 'any'
    diff_fn = globals()[f'check_{diff}']
    action_fn = globals()[f'action_{matches.group("action")}']
    action_args = matches.group('action_args')
    subjects = matches.group('subj')
    log.debug(f"Looking for '{subjects}'")
    res = diff_fn(results.get(subjects), previous_results.get(subjects, []))
    log.debug(f"Rule: {rule}; result: {res}")
    if (not inverse and not res) or (inverse and res):
        action_fn(rule, res, action_args)

        
def expect_rule_list_compare(rule, matches, results, previous_results):
    quantifier = matches.group('quantifier')
    list1 = matches.group('list1')
    list2 = matches.group('list2')    
    action_fn = globals()[f'action_{matches.group("action")}']
    action_args = matches.group('action_args')
    print(results)
    res = check_added(results.get(list1), results.get(list2))
    if res:
        action_fn(rule, res, action_args)


expect_regexes = [
    (expect_rule_unary, re.compile(r'''^(?P<no>not? )?((?P<diff>[^ ]+) )?(?P<subj>[^ ,]+),? otherwise (?P<action>[^ ]+) (?P<action_args>.+)$''')),
    (expect_rule_list_compare, re.compile(r'''^(?P<quantifier>all )(?P<list1>[^ ]+) in (?P<list2>[^ ,]+),? otherwise (?P<action>[^ ]+) (?P<action_args>.+)$''')),
]        
        
def check_added(new_list, old_list):
    n = set(new_list)
    o = set(old_list)
    return list(n - o)

def check_any(new_list, old_list):
    return new_list

def action_alert(rule, findings, action_args):
    print (f"\n**** FOUND VIOLATION OF '{rule}':\n '{findings!r}'\n****\n")

@contextmanager
def force_ip_connection(ip):
    def patched_create_connection(address, *args, **kwargs):
        """Wrap urllib3's create_connection to resolve the name elsewhere"""
        # resolve hostname to an ip address; use your own
        # resolver here, as otherwise the system resolver will be used.
        host, port = address
        hostname = ip
        return _orig_create_connection((hostname, port), *args, **kwargs)

    connection.create_connection = patched_create_connection
    yield
    connection.create_connection = _orig_create_connection
    
