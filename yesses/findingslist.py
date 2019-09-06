import logging
from .state import State
from .utils import clean_expression
from functools import reduce
    
log = logging.getLogger('findingslist')

class FindingsList:

    class NotAUseExpression(Exception):
        pass
    
    def __init__(self, persist_path, resume_path, initial):
        self.current_findings = initial
        self.persist = State(persist_path)
        self.resume = State(resume_path)
        self.persist.load()
        self.previous_findings = self.persist.data
        self.ignore_existing = False

    def get(self, key):
        if not key in self.current_findings:
            raise Exception(f"Unknown findings key: {key}; existing keys are: {', '.join(self.current_findings.keys())}")
        return self.current_findings[key]

    def set(self, key, value):
        if not self.ignore_existing and key in self.current_findings:
            raise Exception(f"Storing findings in key {key} would overwrite existing findings.")
        self.current_findings[key] = value

    def get_previous(self, key, default):
        return self.previous_findings.get(key, default)
        
    def save_persist(self):
        self.persist.data = self.current_findings
        self.persist.save()

    def save_resume(self, step):
        self.resume.data[step] = self.current_findings
        self.resume.data['_step'] = step
        self.resume.save()

    def load_resume(self, step=None):
        log.debug("Loading findings list resume data")
        self.resume.load()
        if step is None:
            step = self.resume.data['_step']
        self.current_findings = self.resume.data[step]
        return step

    def get_from_use_expression(self, use_expr):
        if type(use_expr) is not str or not use_expr.startswith('use '):
            raise self.NotAUseExpression
        
        keys = use_expr.split(' ', 1)[1].split(' and ')
        all_entries = []

        for key in keys:
            all_entries += self.get(key)
        unique = reduce(lambda l, x: l if x in l else l+[x], all_entries, [])
        return unique
