#!/usr/bin/env python3

import inspect
import importlib
import subprocess

from jinja2 import Environment, FileSystemLoader
from pathlib import Path

import yaml

INFILE = Path('README.j2')
OUTFILE = Path('README.md')

modules = ['scan', 'discover']

template_modules = {}

for m in modules:
    module = importlib.import_module(f"yesses.{m}")
    template_modules[m] = list(member[1] for member in inspect.getmembers(module) if type(member[1]) == type)

def jinja2_yaml_filter(obj):
    return yaml.safe_dump(obj, default_flow_style=False)

res = subprocess.run(['./run.py', '--help'], stdout=subprocess.PIPE)
usage = str(res.stdout, 'ascii')

    
file_loader = FileSystemLoader(str(INFILE.parent))
env = Environment(loader=file_loader)
env.filters['yaml'] = jinja2_yaml_filter
template = env.get_template(INFILE.name)
output = template.render(modules=template_modules, usage=usage)
OUTFILE.write_text(output)
