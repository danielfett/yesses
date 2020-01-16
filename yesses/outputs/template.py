from jinja2 import Environment, FileSystemLoader
from pathlib import Path
from datetime import datetime

import logging

log = logging.getLogger("output/template")


class Template:
    def __init__(self, filename, template):
        self.filename = Path(datetime.now().strftime(filename))
        self.template = Path(template)

    def run(self, alertslist, steps, raw_config, time):
        file_loader = FileSystemLoader(str(self.template.parent))
        env = Environment(loader=file_loader)
        template = env.get_template(self.template.name)
        output = template.render(
            time=time, steps=steps, raw_config=raw_config, **alertslist.get_vars()
        )

        self.filename.write_text(output)
        log.info(f"Wrote report to {self.filename} using template {self.template}")
