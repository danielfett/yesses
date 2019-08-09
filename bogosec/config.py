import yaml
from pathlib import Path
from logging.config import dictConfig

class Config:
    def __init__(self, filename):
        self.configfilepath = Path(filename)
        if self.configfilepath.exists():
            with self.configfilepath.open() as f:
                text = f.read()
            self.data = yaml.load(text)
        else:
            raise Exception("Config file does not exist.")

        self.initial_data = self.data.get('data', {})
        
        if 'statefile' in self.data:
            self.statefilepath = self.data['statefile']
        else:
            self.statefilepath = self.configfilepath.with_suffix(".state")

        self.steps = self.data['run']

        if 'output' in self.data:
            dictConfig(self.data['output'])
        
