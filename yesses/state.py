import yaml
from pathlib import Path
import yesses.scan.tls_settings

class State:
    def __init__(self, filename, fresh):
        self.statefilepath = Path(filename)
        self.data = {}
        self.fresh = fresh

    def load(self):
        if self.fresh or not self.statefilepath.exists():
            self.data = {}
        else:
            with self.statefilepath.open() as f:
                text = f.read()
            self.data = yaml.full_load(text)

    def save(self):
        with self.statefilepath.open('w') as f:
            f.write(yaml.dump(self.data))
            

        
