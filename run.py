#!/usr/bin/env python3

import logging
import sys

from yesses import Config
from io import StringIO as StringBuffer

format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.INFO, format=format)
        
log = logging.getLogger('run')

class YessesRunner:

    
    def __init__(self, configfile):
        self.config = Config(configfile)

        self.findings = self.config.get_findingslist()
        self.alerts = self.config.get_alertslist()
        self.log_buffer = StringBuffer()
        
        log_handler = logging.StreamHandler(self.log_buffer)
        logging.getLogger().addHandler(log_handler)
        
        
    def run(self, do_resume, repeat):
        log.warning(f"Starting run. do_resume={do_resume}, repeat={repeat}")
        if do_resume:
            skip_to = self.findings.load_resume()
            self.alerts.load_resume()
        if repeat is not None:
            if do_resume:
                skip_to -= repeat    
            else:
                skip_to = len(self.config.steps) - repeat
            if skip_to < 0:
                raise Exception(f"There are {len(self.config.steps)} steps, we were asked to resume from step {skip_to}. That does not work.")
            self.findings.load_resume(skip_to)
            self.alerts.load_resume(skip_to)

        if do_resume or repeat is not None:
            log.info(f"Resuming from step {skip_to}.")
        for step in self.config.steps:
            if not (do_resume or repeat is not None) or step.number > skip_to:
                log.info(f"Step: {step.action}")
                self.alerts.collect(step.execute(self.findings))
            self.findings.save_resume(step.number)
            self.alerts.save_resume(step.number)

        for output in self.config.outputs:
            output.run(self.alerts)

        self.findings.save_persist()
            

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Tool to scan for network and web security features')
    parser.add_argument('configfile', help='Config file in yaml format', type=argparse.FileType('r'))
    parser.add_argument('--verbose', '-v', action='count', help='Increase debug level')
    parser.add_argument('--resume', '-r', action='store_true', help='Resume scanning from existing resumefile', default=None)
    parser.add_argument('--repeat', type=int, metavar='N', help='Repeat last N steps of run (for debugging). Will inhibit warnings of duplicate output variables.', default=None)

    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    s = YessesRunner(args.configfile)
    s.run(args.resume, args.repeat)
        
