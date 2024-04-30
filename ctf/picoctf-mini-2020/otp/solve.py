from angr import *
from claripy import *

x = BVS('x', 100 * 8)

proj = Project("./otp", load_options={'main_opts': {'base_addr': 0x0}})
state = proj.factory.entry_state(args=['./otp', x])
sm = proj.factory.simulation_manager(state)
# state.options.discard("LAZY_SOLVES")


def char(state, byte):
    return state.solver.And(byte <= '~', byte >= ' ')

# for byte in x.chop(8):
#     state.solver.add(
#         state.solver.Or(
#             state.solver.And(byte >= b'0', byte <= b'9'),
#             state.solver.And(byte >= b'a', byte <= b'f')
#         )
#     )


# 0x9e5

def is_successful(state):
    # stdout_output = state.posix.dumps(sys.stdout.fileno())  # (1)
    # print(str(state.solver.eval(x, cast_to=bytes)))
    print({key:len(value) for key,value in sm.stashes.items()})
    for j in sm.active:
        print(hex(j.addr))
    return state.addr == 0x874


def prune(sim):

    print({key:len(value) for key,value in sm.stashes.items()})
    # if(len(sim.active) < 8):
    #     return sim
    # prune_val = sim.active[0].addr
    # if(len([x for x in sim.active if x.addr == prune_val])):
    #     print("Pruning!!")
    #     sim.drop(lambda s: s.addr != prune_val)
        # for i in sim.active:
        #     print(list(i.log.actions)
        # x = len(sim.active)
        # print(x)
        # def drop(s):
        #     x =- 1
        #     print(x)
        #     return x > 1
        # sim.drop(drop)
        # print(sim.active[0].solver.eval(x, cast_to=bytes).decode('ascii'))
    return sim

sm.explore(find=0x9e5, avoid=0x9c6,step_func=prune)

if sm.found:
    print('done.')
    for i in sm.found:

        print(str(i.solver.eval(x, cast_to=bytes)))