from .find import find
from .expect import expect

def execute(step, temp_findings, final_findings):
    
    verbs_order = [
        ('find', find),
        ('expect', expect),
    ] # order is important: 'find' must be run before 'expect'

    for verb_name, verb_function in verbs_order:
        if not verb_name in step:
            continue
        verb_function(step[verb_name], temp_findings, final_findings)

