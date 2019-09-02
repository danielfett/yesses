import re
import logging
from yesses import alerts
from yesses import FindingsList

from yesses.utils import clean_expression

log = logging.getLogger('verbs/expect')

def expect(step, verb_contents, _, final_findings):
    log.debug(f"Current expect findings: {verb_contents!r}")
    for rule in verb_contents:
        rule = clean_expression(rule)
        for handle_fn, regex in expect_regexes:
            matches = re.match(regex, rule)
            if matches is not None:
                yield from handle_fn(step, rule, matches, final_findings)
                break
        else:
            raise Exception(f"Illegal rule: {rule} (does not match any expect rule format)")
    

def expect_rule_unary(step, rule, matches, findings):
    inverse = matches.group('no')
    diff = matches.group("diff")
    if diff in ('some', '', None):
        diff = 'any'
    diff_fn = globals()[f'check_{diff}']
    action_fn = globals()[f'action_{matches.group("action")}']
    action_args = matches.group('action_args')
    subjects = matches.group('subj')
    log.debug(f"Looking for '{subjects}'")
    res = diff_fn(
        findings.get(subjects),
        findings.get_previous(subjects, [])
    )
    log.debug(f"Rule: {rule}; finding: {res}")
    if (not inverse and not res) or (inverse and res):
        yield from action_fn(step, rule, res, action_args)

        
def expect_rule_list_compare(step, rule, matches, findings):
    quantifier = matches.group('quantifier')
    list1 = matches.group('list1')
    list2 = matches.group('list2')    
    action_fn = globals()[f'action_{matches.group("action")}']
    action_args = matches.group('action_args')

    res = check_added(
        findings.get(list1),
        findings.get(list2)
    )
    if res:
        yield action_fn(step, rule, res, action_args)


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

def action_alert(step, rule, findings, action_args):
    yield Alert(
        severity=Alert.Severity.parse(action_args),
        violated_rule=rule,
        findings=findings,
        step=step
    )
