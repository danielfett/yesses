import yaml
from pathlib import Path
from .findingslist import FindingsList
from .alertslist import AlertsList
from .step import Step
from .output import Output

class Config:
    def __init__(self, configfile, fresh=False):
        self.data = yaml.full_load(configfile.read())
        self.fresh = fresh
        
        self.configfilepath = Path(configfile.name)

        self.initial_data = self.data.get('data', {})
        
        self.statefilepath = self.configfilepath.with_suffix(".state")
        self.resumefilepath = self.configfilepath.with_suffix(".resume")
        self.alertsresumefilepath = self.configfilepath.with_suffix(".alerts")

        self.steps = list(
            Step(raw, number) for raw, number in zip(self.data['run'], range(len(self.data['run'])))
        )

        self.outputs = list(
            Output(raw) for raw in self.data['output']
        )
        
    def get_findingslist(self):
        return FindingsList(
            self.statefilepath,
            self.resumefilepath,
            self.initial_data,
            self.fresh
        )

    def get_alertslist(self):
        return AlertsList(
            self.alertsresumefilepath,
            self.fresh
        )
