import logging
from .state import State
from .parsers import UseParser
from functools import reduce

    
log = logging.getLogger('findingslist')

class FindingsList:

    class NotAUseExpression(Exception):
        pass
    
    def __init__(self, persist_path, resume_path, initial, fresh=False):
        self.current_findings = initial
        self.persist = State(persist_path, fresh)
        self.resume = State(resume_path, fresh)
        self.persist.load()
        self.previous_findings = self.persist.data
        self.ignore_existing = False

    def get(self, key, attributes=None):
        if not key in self.current_findings:
            raise Exception(f"Unknown findings key: {key}; existing keys are: {', '.join(self.current_findings.keys())}")
        out = self.current_findings[key]
        if attributes is not None:
            return [
                {k:el[k] for k in attributes} for el in out
            ]
        return out

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
        self.resume.load()
        if step is None:
            step = self.resume.data['_step']
        log.debug(f"Loading findings list resume data, step={step}")
        self.current_findings = self.resume.data[step]
        self.ignore_existing = True
        return step

    def get_from_use_expression(self, use_expr):
        if type(use_expr) is not str or not use_expr.startswith('use '):
            return use_expr

        res = UseParser.parse(use_expr)
        
        all_entries = []

        for group in res:
            for entry in self.get(group.key):
                if not entry in all_entries:
                    all_entries.append(entry)
                    
        return all_entries

    def get_common_and_missing_items(self, key1, key2):
        """Return items that are in findings with key1 and with key2; and
        items that are in findings with key1 but not in those with
        key2; and a boolean indicating if the lists are the same.

        """
        common_attrs = self.find_common_attributes(key1, key2)
        items1 = self.get(key1, common_attrs)
        items2 = self.get(key2, common_attrs)
        common_items = [item for item in items1 if item in items2]
        missing_items = [item for item in items1 if item not in items2]
        equals = len(common_items) == len(items1) == len(items2):
            
        return common_items, missing_items, equals

    def get_added_items(self, key):
        """Return items that appear in the current findings list with the
        given key, but not in the previous one.

        """
        current = self.get(key)
        previous = self.get_previous(key, [])
        added = [item for item in current if item not in previous]
        return added
        
    def find_common_attributes(self, *keys):
        """Find one or more attributes that each entry in each of the
        lists has in common. This function compares only the first
        member of each list and assumes that all further elements have
        the same attributes. This is enforced in other places in the
        code.

        """

        common_attrs = None
        for k in keys:
            all_items = self.get(k)
            if len(all_items) == 0:
                return ['DOES_NOT_MATTER']
            attrs = set(all_items[0].keys())
            if common_attrs is None:
                common_attrs = attrs
            else:
                common_attrs &= attrs

        if len(common_attrs) == 0:
            raise Exception(f"Unable to compare the findings lists {keys} (no common attributes).")
        return common_attrs
        
        
