from jinja2 import Environment, FileSystemLoader
import os
from yesses.alerts import Alert

class AlertsList:
    MAIN_FILE = 'main.j2'
    
    def __init__(self):
        self.alerts = []

    def collect(self, alerts):
        self.alerts += alerts

    def to_string(self):
        yield "****** BEGIN ALERTS ******\n"
        for alert in self.alerts:
            yield str(alert)
            yield "\n\n"
        yield "****** END ALERTS ******"

    def get_vars(self):
        return {
            'alerts': self.alerts,
            'severity': Alert.Severity,
        }
            
    def render(self, target_file, format, template_folder):
        path = os.path.join(template_folder, format)
        file_loader = FileSystemLoader(path)
        env = Environment(loader=file_loader)
        template = env.get_template(self.MAIN_FILE)
        target_file.write(template.render(**self.get_vars()))
