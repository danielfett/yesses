#!/usr/bin/env python3

import logging
import sys

from yesses import Runner

log = logging.getLogger('run')


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Tool to scan for network and web security features')
    parser.add_argument('configfile', help='Config file in yaml format', type=argparse.FileType('r'))
    parser.add_argument('--verbose', '-v', action='count', help='Increase debug level')
    parser.add_argument('--resume', '-r', action='store_true', help='Resume scanning from existing resumefile', default=None)
    parser.add_argument('--repeat', type=int, metavar='N', help='Repeat last N steps of run (for debugging). Will inhibit warnings of duplicate output variables.', default=None)
    parser.add_argument('--fresh', '-f', action='store_true', help='Do not use existing state files. Usage of this required when datastructures in this application changed.', default=False)

    args = parser.parse_args()

    log_handler = logging.StreamHandler(sys.stdout)
    log_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    log_handler.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    logging.getLogger().addHandler(log_handler)
    logging.getLogger().setLevel(logging.DEBUG)
    
    
    runner = Runner(args.configfile, args.fresh)
    runner.run(args.resume, args.repeat)
        
