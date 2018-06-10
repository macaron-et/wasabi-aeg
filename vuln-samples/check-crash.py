#!/usr/bin/python2
from pwn import *
import os, sys
import glob

# context.log_level = 'debug'
context.log_level = 'warn'
context.terminal = '/bin/bash'

def bp():
    raw_input('preess enter to continue... ')

INPUT_GLOB = sys.argv[1]
log.info(INPUT_GLOB)
log.info(glob.glob(INPUT_GLOB))
for INPUT_FILE in sorted(glob.glob(INPUT_GLOB)):
    r = process("./fl0ppy")

    # bp()

    # gdb.attach(r, 'c')

    log.info('input file: {}'.format(INPUT_FILE))
    with open(INPUT_FILE) as f:
        _input = f.read()

    for x in _input.split():
        if r.poll() is None:
            # print(x)
            r.sendline(x)
        if r.poll() is None:
            res = r.recv(1024)
            # print(res)

    exit_code = r.poll()
    print("{}\texit code: {}".format(INPUT_FILE, exit_code))