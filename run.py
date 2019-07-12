#!/usr/bin/env python3
# Discover domains
# -> If new/changed, notify!
# Discover IPs behind domains
# -> If new/changed, notify!
# Discover ports open on IPs
# -> If new/changed, notify!
# Discover cipher suites available on these IPs, with domains.
# -> If new/changed, notify!
#

from bogosec import Config, State, verbs, FindingsList
from importlib import import_module
import re

import logging
logging.basicConfig(level=logging.DEBUG)

log = logging.getLogger('run')

class BogoSec:

    
    def __init__(self, configfile):
        self.config = Config(configfile)
        self.findings = FindingsList(
            self.config.data['statefile'],
            self.config.data.get('data', {})
        )
        self.verbs = { name: getattr(verbs, name) for name in
                       dir(verbs) if not name.startswith('__') }
        
    def run(self):
        for step in self.config.data['run']:
            action = list(step.keys())[0]
            args = step[action] if type(step[action]) == list else []
            kwargs = step[action] if type(step[action]) == dict else {}

            kwargs_modified = {}
            for name, value in kwargs.items():
                try:
                    kwargs_modified[name] = self.findings.get_from_use_expression(value)
                except FindingsList.NotAUseExpression:
                    kwargs_modified[name] = value
            
            temp_findings = self.call_class_from_action(
                action,
                *args,
                **kwargs_modified
            )
            verbs.execute(step, temp_findings, self.findings)

    def save(self):
        self.state.data = self.findings
        self.state.save()
            
    def call_class_from_action(self, action, *args, **kwargs):
        mod, cls = self.split_action(action)
        res = getattr(import_module(f'bogosec.{mod}'), cls)(
            *args,
            **kwargs
        ).run()
        return res

    @staticmethod
    def split_action(action):
        verb, subj = action.split(' ', 1)
        def uc(match):
            return match.group(1).upper()
        cls = re.sub('( [a-z])', uc, subj)
        cls = cls.replace(' ', '')
        return verb, cls
        
    #def notify(self):
    #    n = NotifyChangedCollection()
    #    messages = [n.compare_lists(self.findings['discover']['domains_and_ips']['ips']


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Tool to scan for network and web security features')
    parser.add_argument('configfile', help='Config file in yaml format')
    args = parser.parse_args()
    
    s = BogoSec(args.configfile)
    s.run()
    s.save()

        
