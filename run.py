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
from io import StringIO as StringBuffer

import re

import logging
format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.INFO, format=format)
        
log = logging.getLogger('run')

class BogoSec:

    
    def __init__(self, configfile):
        self.config = Config(configfile)

        self.findings = FindingsList(
            self.config.statefilepath,
            self.config.initial_data
        )
        self.log_buffer = StringBuffer()
        log_handler = logging.StreamHandler(self.log_buffer)
        logging.getLogger().addHandler(log_handler)
        
        
    def run(self):
        for step in self.config.steps:
            action = list(step.keys())[0]
            args = step[action] if type(step[action]) == list else []
            kwargs = step[action] if type(step[action]) == dict else {}

            kwargs_modified = {}
            for name, value in kwargs.items():
                try:
                    kwargs_modified[name] = self.findings.get_from_use_expression(value)
                except FindingsList.NotAUseExpression:
                    kwargs_modified[name] = value

            log.info(f"Step: {action}")
            temp_findings = self.call_class_from_action(
                action,
                *args,
                **kwargs_modified
            )
            verbs.execute(step, temp_findings, self.findings)

    def save(self):
        self.findings.save()
            
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
    parser.add_argument('--verbose', '-v', action='count', help='Increase debug level')
    args = parser.parse_args()
    if args.verbose:
        logging.setLevel(logging.DEBUG)
    s = BogoSec(args.configfile)
    s.run()
    s.save()

        
