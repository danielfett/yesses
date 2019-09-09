import yaml
from pathlib import Path
from .findingslist import FindingsList
from .alertslist import AlertsList
from .step import Step
from .output import Output

class Config:
    def __init__(self, configfile, fresh=False):
        self.data = yaml.full_load(configfile.read())
        
        self.configfilepath = Path(configfile.name)

        self.initial_data = self.data.get('data', {})
        
        self.steps = list(
            Step(raw, number) for raw, number in zip(self.data['run'], range(len(self.data['run'])))
        )

        self.outputs = list(
            Output(self, raw) for raw in self.data['output']
        )

        self.findingslist = FindingsList(
            self.configfilepath.with_suffix(".state"),
            self.configfilepath.with_suffix(".resume"),
            self.initial_data,
            fresh
        )

        self.alertslist = AlertsList(
            self.configfilepath.with_suffix(".alerts"),
            fresh
        )
