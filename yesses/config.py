import yaml
from pathlib import Path
from .findingslist import FindingsList
from .alertslist import AlertsList
from .step import Step
from .output import Output


class Config:
    STATE_SUFFIX = ".state"
    RESUME_SUFFIX = ".resume"
    ALERTS_SUFFIX = ".alerts"

    def __init__(self, configfile, fresh=False):
        self.data = yaml.full_load(configfile.read())

        self.configfilepath = Path(configfile.name)

        self.initial_data = self.data.get("data", {})

        self.steps = []
        for raw, number in zip(self.data["run"], range(len(self.data["run"]))):
            try:
                self.steps.append(Step(raw, number))
            except Exception as e:
                raise Exception(f"Unable to initialize step no. {number}.")

        self.outputs = list(Output(self, raw) for raw in self.data.get("output", []))

        self.findingslist = FindingsList(
            self.configfilepath.with_suffix(self.STATE_SUFFIX),
            self.configfilepath.with_suffix(self.RESUME_SUFFIX),
            self.initial_data,
            fresh,
        )

        self.alertslist = AlertsList(
            self.configfilepath.with_suffix(self.ALERTS_SUFFIX), fresh
        )

    def load_resume(self, step=None):
        skip_to = self.findingslist.load_resume(step)
        skip_to_2 = self.alertslist.load_resume(step)
        if skip_to != skip_to_2:
            raise Exception(
                f"Inconsistent file state. Findings list is in Step {skip_to}, alerts list is in Step {skip_to_2}. Cannot resume/repeat."
            )
        for s in self.steps:
            s.load_findings(self.findingslist)
        return skip_to

    def save_resume(self, step):
        self.findingslist.save_resume(step)
        self.alertslist.save_resume(step)

    def save_persist(self):
        self.findingslist.save_persist()
