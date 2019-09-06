import yaml
from pathlib import Path

class State:
    def __init__(self, filename):
        self.statefilepath = Path(filename)
        self.data = {}

    def load(self):
        if not self.statefilepath.exists():
            self.data = {}
        else:
            with self.statefilepath.open() as f:
                text = f.read()
            self.data = yaml.full_load(text)

    def save(self):
        with self.statefilepath.open('w') as f:
            f.write(yaml.dump(self.data))
            

        
