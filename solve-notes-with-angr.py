#!/usr/bin/python2
# encoding: utf-8
import angr #the main framework
import claripy
from hexdump import hexdump

rebased_addr = lambda x: proj.loader.find_symbol(x).rebased_addr

### ログレベルをデバッグモードに
angr.manager.l.setLevel("DEBUG")

### デバッグモード
DEBUG = False

CRASH_INPUT_FILE = "./vuln-samples/crash-inputs/notes-1"
with open(CRASH_INPUT_FILE) as f:
    crash_input = f.read()
hexdump(crash_input)

### 解析対象を読み込む（ベタ書きでなく変数で書いてくと吉）
ELF_FILE = "./vuln-samples/notes"
#### 読み込むときに、CLEローダーでlibc.soを読み込まないように設定する
#### （Trueにしてもlibc.soの関数はシンボリック化されているので影響がない）
proj = angr.Project(ELF_FILE, load_options={'auto_load_libs': False})

def tracer_linux(filename, test_name, stdin):
    p = angr.Project(filename)

    trace, _, crash_mode, crash_addr = do_trace(p, test_name, stdin)
    s = p.factory.entry_state(mode='tracing', stdin=angr.SimFileStream)
    s.preconstrainer.preconstrain_file(stdin, s.posix.stdin, True)

    simgr = p.factory.simulation_manager(s, save_unsat=True, hierarchy=False, save_unconstrained=crash_mode)
    t = angr.exploration_techniques.Tracer(trace)
    c = angr.exploration_techniques.CrashMonitor(trace=trace, crash_addr=crash_addr)
    if crash_mode:
        simgr.use_technique(c)
    simgr.use_technique(t)
    simgr.use_technique(angr.exploration_techniques.Oppologist())
    return simgr, t

# simgr, _ = tracer_linux(ELF_FILE, 'test', CRASH_INPUT_FILE)
# simgr.run()

### エントリーポイントから実行したときのステートを生成
state = proj.factory.entry_state(args=[ELF_FILE])

### stdin
# with open("./vuln-samples/result-notes/crashes/id:000000,sig:11,src:000000,op:havoc,rep:8") as f:
for i, x in enumerate(crash_input):
    k = state.posix.files[0].read_from(1)
    state.add_constraints(k == x)

### seek to head
state.posix.files[0].seek(0)
state.posix.files[0].length = len(crash_input)

# print '%r' % state.posix.dumps(0)
# exit()

def debug_funcRead(state):
    if state.inspect.mem_read_address.symbolic:
        print 'Read', state.inspect.mem_read_expr, 'from', state.inspect.mem_read_address
        exit()
    else:
        print 'stdin: %r' % state.posix.dumps(0)
        print 'stdout: %r' % state.posix.dumps(1)

state.inspect.b('mem_read', when=angr.BP_AFTER, action=debug_funcRead)

### 生成したステートをSimulation Managerに読み込む
### （以前はPath Groupだったが、angr 7からsimgrに移行した。詳しくは angr-doc/MIGRATION.md を参照されたし）
simgr = proj.factory.simgr(state)

simgr.use_technique(angr.exploration_techniques.DFS())


### Simulation Managerでシンボリック実行を開始する。
### エラーを吐くステートが出現するまでステップ実行
simgr.explore(find=rebased_addr('instant_win'))
# while True:
#     simgr.step()
#     for act in simgr.active:
#         print act.ip
#         if act.inspect.mem_read_address:
#             print 'Read', act.inspect.mem_read_expr, 'from', act.inspect.mem_read_address
#     # import ipdb; ipdb.set_trace()
