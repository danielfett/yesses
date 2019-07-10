from sectool import Severity, SecMessage

log = logging.getLogger('notify/changed_collection')

# This works for list or for dictionaries that map strings to lists
class NotifyChangedCollection:
    def __init__(self,
                 name,
                 severity_removed=Severity.MEDIUM,
                 severity_added=Severity.HIGH,
                 severity_changed=Severity.HIGH):
        self.name = name
        self.severity_removed = severity_removed
        self.severity_added = severity_added
        self.severity_changed = severity_changed
        

    def compare_dicts_of_lists(self, old, new, name):
        yield from self.compare_lists(old.keys(), new.keys())
        all_keys = set(old.keys()) | set(new.keys())
        for key in all_keys:
            yield from self.compare_lists(
                old.get(key, []),
                new.get(key, []),
                name=f'{name} (key {key})'
            )

    def compare_dicts_of_values(self, old, new, name):
        yield from self.compare_lists(old.keys(), new.keys())
        all_keys = set(old.keys()) | set(new.keys())
        for key in all_keys:
            old_entry = old.get(key, None)
            new_entry = new.get(key, None)
            if old_entry != new_entry:
                yield SecMessage(
                    place=f"{name} (key {key})",
                    message=f"Entry changed: {old_entry!r} (old) → {new_entry!r} (new)",
                    severity=self.severity_changed
                )
            
    def compare_lists(self, old_list, new_list, name):
        old = set(old_list)
        new = set(new_list)
        added = new - old
        removed = old - new
        for entry in added:
            yield SecMessage(
                place=f"{name}",
                message=f"Entry added: None → {new!r} (new)",
                severity=self.severity_added
            )
        
        for entry in removed:
            yield SecMessage(
                place=f"{name}",
                message=f"Entry removed: {old!r} (old) → None",
                severity=self.severity_removed
            )
            
        
