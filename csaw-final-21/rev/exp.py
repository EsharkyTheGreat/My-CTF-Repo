# Import Angr
import angr

# Establish the Angr Project
target = angr.Project('maze_public')

# Specify the desired address which means we have the correct input
desired_adr = 0x4000ce

# Specify the address which if it executes means we don't have the correct input
wrong_adr = 0x400eb

# Establish the entry state
entry_state = target.factory.entry_state(args=["./maze_public", '0>&2'])

# Establish the simulation
simulation = target.factory.simulation_manager(entry_state)

# Start the simulation
simulation.explore(find=desired_adr, avoid=wrong_adr)

solution = simulation.found[0].posix.dumps(0)
print(solution)
