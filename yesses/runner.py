#!/usr/bin/env python3

import logging
from datetime import datetime, timedelta

from yesses import Config

log = logging.getLogger('run')

class Runner:
    def __init__(self, configfile, fresh):
        self.config = Config(configfile, fresh)
        
    def run(self, do_resume=False, repeat=None):
        log.info(f"Starting run. do_resume={do_resume}, repeat={repeat}")
        start = datetime.now()
        if do_resume:
            skip_to = self.config.load_resume()
        if repeat is not None:
            if do_resume:
                skip_to -= repeat    
            else:
                skip_to = len(self.config.steps) - repeat
            if skip_to < 0:
                raise Exception(f"There are {len(self.config.steps)} steps, we were asked to resume from step {skip_to}. That does not work.")
            self.config.load_resume(skip_to)

        if do_resume or repeat is not None:
            log.info(f"Resuming after step {skip_to}.")
        for step in self.config.steps:
            if not (do_resume or repeat is not None) or step.number > skip_to:
                log.info(f"Step: {step.action}")
                step.load_findings(self.config.findingslist)
                self.config.alertslist.collect(step.execute())
                self.config.save_resume(step.number)
            
        end = datetime.now()
        time = end-start
        
        for output in self.config.outputs:
            output.run(time)

        self.config.save_persist()
        log.info(f"Run finished in {time}s.")
