#!/usr/bin/env python3

import logging
import sys
from pathlib import Path
from yesses import Runner, all_modules, Config
from datetime import datetime

log = logging.getLogger('run')

scriptpath = Path(__file__).resolve().parent

README_INFILE = scriptpath / Path('templates/README.j2')
README_OUTFILE = scriptpath / Path('README.md')


def test():
    modules = all_modules()
    for category, cat_modules in modules.items():
        for module in cat_modules:
            print (f"Testing {category} {module.__name__}")
            module.selftest(standalone=False)

    return modules


def generate_readme(usage):
    import yaml
    from jinja2 import Environment, FileSystemLoader

    all_modules_tested = test()

    def jinja2_yaml_filter(obj):
        out = yaml.safe_dump(obj, default_flow_style=False, default_style='')
        return out[:-4] if out.endswith("...\n") else out

    file_loader = FileSystemLoader(str(README_INFILE.parent))
    env = Environment(loader=file_loader)
    env.filters['yaml'] = jinja2_yaml_filter
    template = env.get_template(README_INFILE.name)
    output = template.render(modules=all_modules_tested, usage=usage, time=datetime.now())
    README_OUTFILE.write_text(output)



if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description='Tool to scan for network and web security features')
    parser.add_argument('configfile', nargs='?', help='Config file in yaml format. Required unless --test or --generate-readme are used.', type=argparse.FileType('r'))
    parser.add_argument('--verbose', '-v', action='count', help='Increase debug level to show debug messages.')
    parser.add_argument('--resume', '-r', action='store_true', help='Resume scanning from existing resumefile.', default=None)
    parser.add_argument('--repeat', type=int, metavar='N', help='Repeat last N steps of run (for debugging). Will inhibit warnings of duplicate output variables.', default=None)
    parser.add_argument('--fresh', '-f', action='store_true', help='Do not use existing state files. Usage of this required when datastructures in this application changed.', default=False)
    parser.add_argument('--test', action='store_true', help='Run a self-test. This executes the examples contained in all modules.')
    parser.add_argument('--generate-readme', action='store_true', help=f'Run a self-test (as above) and generate the file {README_OUTFILE.name} using the test results.')

    args = parser.parse_args()

    log_handler = logging.StreamHandler(sys.stdout)
    log_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    log_handler.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    logging.getLogger().addHandler(log_handler)
    logging.getLogger().setLevel(logging.DEBUG)
    
    if args.generate_readme:
        generate_readme(parser.format_help())
    elif args.test:
        test()
    else:
        if not args.configfile:
            parser.error("configfile missing.")
        runner = Runner(args.configfile, args.fresh)
        runner.run(args.resume, args.repeat)
        
    
