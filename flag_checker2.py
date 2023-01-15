#!/usr/bin/python3
import monkeyhex
import angr
import claripy
import logging


def solve():
    proj = angr.Project('flag_checker2')
    state = proj.factory.entry_state(add_options=angr.options.unicorn, remove_options={angr.options.LAZY_SOLVES})
    simgr = proj.factory.simgr(state, veritesting=True)


    TARGET = 0x004011df # memcmp() gives true here. 
    TRAP= [ 0x004011eb, 0x00401190 ]
    simgr.explore(find=TARGET, avoid=TRAP)

    if(len(simgr.found) > 0):
        print(f'Found solution!')
        found = simgr.found[0]
        flag = ''.join([chr(_) for _ in found.posix.dumps(0)])
	 
    return(flag)

def test():
    assert(solve() == 'SHKIB_I_4M_a_b17_mU74nt')

if __name__ == '__main__':
    logging.getLogger('angr.sim_manager').setLevel(logging.INFO)
    print(f'>>> Yaandex flag_checker2 solver <<<')
    print(f'Flag is: {solve()}')


# main():
# [0x00401027]> pdfs
# 0x004010bd size_t size
# 0x004010c0 call sym.imp.malloc
# 0x00401115 const char *s
# 0x00401115 str.Hello_there__Welcome_to_flag_checker_v2.0_
# 0x0040111a call sym.imp.puts
# 0x0040111f const char *format
# 0x0040111f str.Enter_the_flag:_
# 0x00401129 call sym.imp.printf
# 0x0040112e FILE *stream
# 0x00401142 int size
# 0x00401144 char *s
# 0x00401147 call sym.imp.fgets.  <----- Provide 23 char long flag.
# 0x00401174:
# 0x00401178 const char *s
# 0x0040117b call sym.imp.strlen. 
# 0x00401190 const char *s
# 0x00401190 str.Wrong_:__n.    <----- Not 23 bytes long input
# 0x00401195 call sym.imp.puts
# 0x0040119e void *ptr
# 0x004011a1 call sym.imp.free
# 0x004011ad:
# 0x004011b1 int64_t arg3
# 0x004011b9 int64_t arg2
# 0x004011bc int64_t arg1
# 0x004011bf call fcn.00400c14 fcn.00400c14.  <----- This is where the flag encryption happens.
# 0x004011c8 size_t n
# 0x004011d0 const void *s2
# 0x004011d3 const void *s1
# 0x004011d6 call sym.imp.memcmp
# 0x004011df const char *s
# 0x004011df str.Correct_:__Congratz__n <----- memcmp() returned true. So input flag is the same as expected.ß
