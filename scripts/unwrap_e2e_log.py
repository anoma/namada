#!/usr/bin/env python3

# this script takes `expectrl` log outputs, such as the ones emitted by
# e2e tests, and unwraps them into a more readable format

import re
import sys

UNICODE = re.compile(r'\\u{([\da-fA-F]+)}')

def main():
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r') as f:
            process_file(f)
    else:
        process_file(sys.stdin)

def process_file(f):
    for line in f.readlines():
        process_line(line)
    sys.stdout.flush()

def process_line(line):
    prefix = 'read: '
    for m in UNICODE.findall(line):
        line = line.replace(f'\\u{{{m}}}', f'\\u{int(m, 16):04x}')
    line = eval(line[len(prefix):])
    sys.stdout.write(line)

if __name__ == '__main__':
    main()
