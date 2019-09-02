import yaml
from pathlib import Path
from logging.config import dictConfig
from .findingslist import FindingsList

class Config:
    def __init__(self, configfile):
        self.data = yaml.full_load(configfile.read())
        
        self.configfilepath = Path(configfile.name)

        self.initial_data = self.data.get('data', {})
        
        if 'statefile' in self.data:
            self.statefilepath = self.data['statefile']
        else:
            self.statefilepath = self.configfilepath.with_suffix(".state")

        if 'resumefile' in self.data:
            self.resumefilepath = self.data['resumefile']
        else:
            self.resumefilepath = self.configfilepath.with_suffix(".resume")

        self.steps = self.data['run']

        if 'output' in self.data:
            dictConfig(self.data['output'])
        
    def get_findingslist(self):
        return FindingsList(
            self.statefilepath,
            self.resumefilepath,
            self.initial_data
        )
