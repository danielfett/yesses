#!/usr/bin/python3
# Discover domains
# -> If new/changed, notify!
# Discover IPs behind domains
# -> If new/changed, notify!
# Discover ports open on IPs
# -> If new/changed, notify!
# Discover cipher suites available on these IPs, with domains.
# -> If new/changed, notify!
#

from bogosec import Config, State
from importlib import import_module
import re

import logging
logging.basicConfig(level=logging.DEBUG)

log = logging.getLogger('run')

class BogoSec:
    def __init__(self, configfile):
        self.config = Config(configfile)
        self.state = State(self.config.data['statefile'])
        self.previous_results = self.state.data
        self.results = self.config.data.get('data', {})
        
    def run(self):
        for step in self.config.data['run']:
            action = list(step.keys())[0]
            args = step[action] if type(step[action]) == list else []
            kwargs = step[action] if type(step[action]) == dict else {}

            kwargs_modified = {}
            for name, value in kwargs.items():
                if type(value) is str and value.startswith('use '):
                    keys = value.split(' ', 1)[1].split(' and ')
                    all_entries = []
                    for key in keys:
                        all_entries += self.results[key]
                    kwargs_modified[name] = list(set(all_entries))
                else:
                    kwargs_modified[name] = value
            
            results = self.call_class_from_action(
                action,
                *args,
                **kwargs_modified
            )
            for result_key in step.get('find', []):
                if ' as ' in result_key:
                    result_key, alias_key = result_key.split(' as ')
                else:
                    alias_key = result_key
                if not result_key in results:
                    raise Exception(f"Did not find key {result_key} in output of {action}.")
                if alias_key in self.results:
                    raise Exception(f"Taking results in key {alias_key} (orig. {result_key}) from output of {action} would overwrite existing results.")
                self.results[alias_key] = results[result_key]

    def save(self):
        self.state.data = self.results
        self.state.save()
            
    def call_class_from_action(self, action, *args, **kwargs):
        if not ' ' in action:  # single verbs, such as 'expect'
            return getattr(import_module(f'bogosec'), action)(
                self.results,
                self.previous_results,
                *args,
                **kwargs
            )
        else:
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
    #    messages = [n.compare_lists(self.results['discover']['domains_and_ips']['ips']


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Tool to scan for network and web security features')
    parser.add_argument('configfile', help='Config file in yaml format')
    args = parser.parse_args()
    
    s = BogoSec(args.configfile)
    s.run()
    s.save()

        
