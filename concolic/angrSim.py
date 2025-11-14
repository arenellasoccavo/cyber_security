import angr
import sys

# Crea un progetto angr caricando il binario chiamato 'simple'
project = angr.Project('simple')

# Crea uno stato iniziale alla entry point del programma (stato CPU, memoria, file descriptors, ecc.)
initial_state = project.factory.entry_state()

# Crea una SimulationManager a partire dallo stato iniziale.
# La simgr controlla l'esplorazione simbolica (gestione di più stati / percorsi)
simulation = project.factory.simgr(initial_state)

# Funzione di callback che controlla se uno stato è "di successo"
def is_successful(state):
    # Estrae ciò che il programma ha scritto su stdout nello stato corrente
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    # Decodifica il bytes in stringa e verifica se c'è la frase "Access Granted"
    return 'Access Granted' in stdout_output.decode("utf-8")

# Funzione di callback che controlla se uno stato deve essere evitato (abort)
def should_abort(state):
    # Come sopra: prende ciò che è stato scritto su stdout
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    # Se il programma ha stampato "Access Denied" consideriamo questo stato da evitare
    return 'Access Denied' in stdout_output.decode("utf-8")

# Avvia l'esplorazione simbolica:
# - find: condizione che indica quando abbiamo trovato una soluzione valida
# - avoid: condizione che specifica quali stati evitare/terminare
simulation.explore(find=is_successful, avoid=should_abort)

# Se la SimulationManager ha trovato almeno uno stato che soddisfa is_successful
if simulation.found:
    solution_state = simulation.found[0]            # prendi il primo stato trovato
    print("Found solution")
    # Stampa (sul nostro stdout reale) quello che il programma si aspetta in stdin per questo stato
    # Di solito contiene la password o l'input che porta allo stato di successo
    print(solution_state.posix.dumps(sys.stdin.fileno()))
else:
    # Se non sono stati trovati stati di successo, solleva un'eccezione
    raise Exception('Could not find the password')

