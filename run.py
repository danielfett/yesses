#!/usr/bin/env python3

import logging
import sys
from pathlib import Path
from yesses import Runner, all_modules, Config
from yesses.module import YModule
from datetime import datetime
from json import dumps, loads
from shlex import quote
from terminaltables import SingleTable

log = logging.getLogger("run")

scriptpath = Path(__file__).resolve().parent

README_INFILE = scriptpath / Path("templates/README.j2")
README_OUTFILE = Path("README.md")


def test():
    modules = all_modules()
    for category, cat_modules in modules.items():
        for module in cat_modules:
            print(f"Testing {category} {module.__name__}")
            module.selftest(standalone=False)

    return modules


def generate_readme(usage, path):
    import yaml
    from jinja2 import Environment, FileSystemLoader

    all_modules_tested = test()

    def jinja2_yaml_filter(obj):
        out = yaml.safe_dump(obj, default_flow_style=False, default_style="")
        return out[:-4] if out.endswith("...\n") else out

    file_loader = FileSystemLoader(str(README_INFILE.parent))
    env = Environment(loader=file_loader)
    env.filters["yaml"] = jinja2_yaml_filter
    template = env.get_template(README_INFILE.name)
    output = template.render(
        modules=all_modules_tested, usage=usage, time=datetime.now()
    )
    (Path(path) / README_OUTFILE).write_text(output)


def build_module_subparsers(parser):
    # Add parsers for all submodules
    modules = all_modules()
    available_modules = []
    for category, cat_modules in modules.items():
        for module in cat_modules:
            available_modules.append(f"'{category} {module.name()}'")

    subparsers = parser.add_subparsers(
        title="modules",
        description="Run a module directly without configuration file. To get help on the usage of a module, run this command with 'MODULE --help'. Remember that module names must be in quotes or the space must be escaped.",
        metavar="MODULE",
        help=f"Available modules: {', '.join(available_modules)}",
        dest="module_name",
    )
    for category, cat_modules in modules.items():
        for module in cat_modules:
            name = f"{category} {module.name()}"
            subparser = subparsers.add_parser(
                name,
                description=module.__doc__,
                formatter_class=argparse.RawDescriptionHelpFormatter,
            )

            for input_name, input_props in module.INPUTS.items():
                if input_props["required_keys"] is None:
                    extra_help = ""
                elif input_props.get("unwrap", False):
                    extra_help = ""
                else:
                    extra_help = " JSON objects, required key(s) for each object: " + (
                        ", ".join(input_props["required_keys"])
                    )

                metavar = input_name.rstrip("s").upper()

                default = input_props.get("default", None)
                if "default" in input_props:
                    if input_props["required_keys"] is None:
                        default_text = str(default)
                    elif input_props.get("unwrap", False):
                        default_text = " ".join(
                            quote(str(d[input_props["required_keys"][0]]))
                            for d in default
                        )
                    else:
                        default_text = " ".join(quote(dumps(el)) for el in default)

                    default_text = (
                        "see README.md" if len(default_text) > 125 else default_text
                    )
                    extra_help += f" (Default: {default_text})"

                    subparser.add_argument(
                        f"--{input_name}",
                        help=input_props["description"] + extra_help,
                        nargs=None if input_props["required_keys"] is None else "*",
                        metavar=metavar,
                    )
                else:
                    subparser.add_argument(
                        f"--{input_name}",
                        help=input_props["description"] + extra_help,
                        required=True,
                        nargs=None if input_props["required_keys"] is None else "*",
                        metavar=metavar,
                    )


def run_module_from_commandline(args):
    module = YModule.class_from_string(args.module_name)
    module_input = {}
    for input_name, input_props in module.INPUTS.items():
        if getattr(args, input_name, None) is None:
            continue
        if input_props["required_keys"] is None:
            module_input[input_name] = getattr(args, input_name)
        elif input_props.get("unwrap", False):
            # The stored value will be a list already, we just need to wrap it.
            module_input[input_name] = [
                {input_props["required_keys"][0]: v} for v in getattr(args, input_name)
            ]
        else:
            module_input[input_name] = [loads(v) for v in getattr(args, input_name)]

    instance = module(step=None, **module_input)
    results = instance.run_module()
    print("Findings:\n")
    no_results = []
    for output_name, findings in results.items():
        if len(findings) == 0:
            no_results.append(output_name)
            continue

        output_props = module.find_matching_output_field(output_name)[1]

        keys = output_props["provided_keys"]
        data = [[k for k in keys]]
        for row in results[output_name]:
            data.append([prettyprint_value(row[k]) for k in keys])
        table_instance = SingleTable(data, output_name)
        print(table_instance.table)
        print(f"{output_name}: {output_props['description']}\n")

    print(f"No findings for: {', '.join(no_results)}")


def prettyprint_value(val):
    if type(val) is list:
        return "\n".join(val)
    else:
        return val


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Tool to scan for network and web security features"
    )
    parser.add_argument(
        "--config",
        "-c",
        nargs="?",
        help="Config file in yaml format. Required unless --test or --generate-readme are used.",
        type=argparse.FileType("r"),
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        help="Increase debug level to show debug messages.",
    )
    parser.add_argument(
        "--resume",
        "-r",
        action="store_true",
        help="Resume scanning from existing resumefile.",
        default=None,
    )
    parser.add_argument(
        "--repeat",
        type=int,
        metavar="N",
        help="Repeat last N steps of run (for debugging). Will inhibit warnings of duplicate output variables.",
        default=None,
    )
    parser.add_argument(
        "--fresh",
        "-f",
        action="store_true",
        help="Do not use existing state files. Usage of this required when datastructures in this application changed.",
        default=False,
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run a self-test. This executes the examples contained in all modules.",
    )
    parser.add_argument(
        "--unittests",
        action="store_true",
        help="Run all tests which are defined in /tests/test_cases.",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="If '--unittests' is specified the test environment will be rebuild from scratch.",
    )
    parser.add_argument(
        "--generate-readme",
        type=str,
        nargs="?",
        help=f"Run a self-test (as above) and generate the file {README_OUTFILE.name} using the test results. Optional: path to write file to, defaults to location of this script.",
        const=str(scriptpath),
        metavar="PATH",
        default=None,
    )

    build_module_subparsers(parser)

    args = parser.parse_args()

    log_handler = logging.StreamHandler(sys.stdout)
    log_handler.setFormatter(
        logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    )
    log_handler.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    logging.getLogger().addHandler(log_handler)
    logging.getLogger().setLevel(logging.DEBUG)

    if args.unittests:
        import tests

        arguments = ""
        if args.no_cache:
            arguments = "--no-cache"
        return_status = tests.run_tests.start_environment(arguments)

        sys.exit(return_status)

    elif args.generate_readme is not None:
        generate_readme(parser.format_help(), args.generate_readme)

    elif args.test:
        test()

    elif args.module_name:
        run_module_from_commandline(args)

    else:
        if not args.config:
            parser.error("configfile missing.")
        runner = Runner(args.config, args.fresh)
        runner.run(args.resume, args.repeat)
