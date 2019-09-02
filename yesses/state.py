import yaml
from pathlib import Path

class State:
    def __init__(self, filename):
        self.statefilepath = Path(filename)
        if not self.statefilepath.exists():
            self.data = {}
        else:
            with self.statefilepath.open() as f:
                text = f.read()
            self.data = yaml.load(text)

    def save(self):
        with self.statefilepath.open('w') as f:
            f.write(yaml.dump(self.data))
            

        
