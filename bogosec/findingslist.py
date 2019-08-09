from bogosec import State
from bogosec.utils import clean_expression
from functools import reduce
    
class FindingsList:

    class NotAUseExpression(Exception):
        pass
    
    def __init__(self, persist_path, initial):
        self.current_findings = initial
        self.persist = State(persist_path)
        self.previous_findings = self.persist.data

    def get(self, key):
        if not key in self.current_findings:
            raise Exception(f"Unknown findings key: {key}; existing keys are: {', '.join(self.current_findings.keys())}")
        return self.current_findings[key]

    def set(self, key, value):
        if key in self.current_findings:
            raise Exception(f"Storing findings in key {key} would overwrite existing findings.")
        self.current_findings[key] = value

    def get_previous(self, key, default):
        return self.previous_findings.get(key, default)
        
    def save(self):
        self.persist.data = self.current_findings
        self.persist.save()

    def get_from_use_expression(self, use_expr):
        if type(use_expr) is not str or not use_expr.startswith('use '):
            raise self.NotAUseExpression
        
        keys = use_expr.split(' ', 1)[1].split(' and ')
        all_entries = []
        for key in keys:
            all_entries += self.current_findings.get(key)
        unique = reduce(lambda l, x: l if x in l else l+[x], all_entries, [])
        return unique
