from .alerts import Alert
from .state import State
from datetime import datetime

class AlertsList:
    def __init__(self, resume_path):
        self.alerts = []
        self.resume = State(resume_path)
        self.started = datetime.now()

    def save_resume(self, step):
        self.resume.data[step] = self.alerts
        self.resume.data['_step'] = step
        self.resume.data['_started'] = self.started
        self.resume.save()

    def load_resume(self, step=None):
        self.resume.load()
        if step is None:
            step = self.resume.data['_step']
        self.alerts = self.resume.data[step]
        self.started = self.resume.data['_started']
        return step

    def collect(self, alerts):
        self.alerts.extend(alerts)

    def to_string(self):
        yield "****** BEGIN ALERTS ******\n"
        for alert in self.alerts:
            yield str(alert)
            yield "\n\n"
        yield "****** END ALERTS ******"

    def get_summary(self):
        severities = [s for s in Alert.Severity]
        severities.sort(key=lambda s: s.value, reverse=True)

        summary = []
        max_severity = None
        for s in severities:
            relevant_alerts = list(a for a in self.alerts if a.severity == s)
            summary.append({
                "severity": s,
                "alerts": len(relevant_alerts),
                "findings": sum(len(a.findings) for a in relevant_alerts),
            })
            if len(relevant_alerts) > 0 and max_severity is None:
                max_severity = s

        return summary, max_severity

    def get_vars(self):
        self.alerts.sort(key=lambda alert: alert.severity.value, reverse=True)
        summary_table, max_severity = self.get_summary()
        return {
            'alerts': self.alerts,
            'severity': Alert.Severity,
            'started': self.started,
            'created': datetime.now(),
            'summary': summary_table,
            'max_severity': max_severity,
        }
            
