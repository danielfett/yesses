from jinja2 import Environment, FileSystemLoader
from pathlib import Path

import logging

log = logging.getLogger('output/template')


class Template:
    def __init__(self, filename, template):
        self.filename = Path(filename)
        self.template = Path(template)
    
    def run(self, alertslist, time):
        file_loader = FileSystemLoader(str(self.template.parent))
        env = Environment(loader=file_loader)
        template = env.get_template(self.template.name)
        output = template.render(time=time, **alertslist.get_vars())
        
        self.filename.write_text(output)
        log.info(f"Wrote report to {self.filename} using template {self.template}")
