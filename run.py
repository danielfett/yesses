#!/usr/bin/env python3

import logging
import sys

from yesses import Step, Config, AlertsList
from io import StringIO as StringBuffer

format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.INFO, format=format)
        
log = logging.getLogger('run')

class YessesRunner:

    
    def __init__(self, configfile):
        self.config = Config(configfile)

        self.findings = self.config.get_findingslist()
        self.log_buffer = StringBuffer()
        
        log_handler = logging.StreamHandler(self.log_buffer)
        logging.getLogger().addHandler(log_handler)
        
        
    def run(self, do_resume, repeat):
        alerts = AlertsList()
        log.warning(f"Starting run. do_resume={do_resume}, repeat={repeat}")
        if do_resume:
            skip_to = self.findings.load_resume()
        if repeat:
            if not do_resume:
                self.findings.load_resume()
            if do_resume:
                skip_to -= repeat
            else:
                skip_to = len(self.config.steps) - repeat - 1
            if skip_to < 0:
                raise Exception(f"There are {len(self.config.steps)} steps, we were asked to resume from step {skip_to}. That does not work.")

        if do_resume or repeat:
            log.info(f"Resuming from step {skip_to}.")
        for step_raw, step_number in zip(self.config.steps, range(len(self.config.steps))):
            if not (do_resume or repeat) or step_number > skip_to:
                step = Step(step_raw)
                log.info(f"Step: {step.action}")
                alerts.collect(step.execute(self.findings))
            self.findings.save_resume(step_number)

        return alerts

    def save(self):
        self.findings.save()
            

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Tool to scan for network and web security features')
    parser.add_argument('configfile', help='Config file in yaml format', type=argparse.FileType('r'))
    parser.add_argument('--verbose', '-v', action='count', help='Increase debug level')
    parser.add_argument('--resume', '-r', action='store_true', help='Resume scanning from existing resumefile', default=None)
    parser.add_argument('--repeat', type=int, metavar='N', help='Repeat last N steps of run (for debugging). Will inhibit warnings of duplicate output variables.', default=None)
    parser.add_argument('--template-dir', '-t', nargs='?', default='templates', help="Template directory.")
    parser.add_argument('--format', '-f', nargs='?', default='html', help="What format to use for the output. This defines the subdirectory in the template directory where the main.j2 template file is expected.")
    parser.add_argument('outfile', nargs='?', type=argparse.FileType('w'), default=sys.stdout)
    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    s = YessesRunner(args.configfile)
    alerts = s.run(args.resume, args.repeat)
    s.save()
    alerts.render(args.outfile, args.format, args.template_dir)
        
