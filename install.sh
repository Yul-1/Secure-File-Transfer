
#!/bin/bash

# === AegisTransfer Ubuntu Installer ===
# Questo script automatizza il setup dell'ambiente di sviluppo
# per il server AegisTransfer su sistemi basati su Ubuntu.

set -e # Esce immediatamente se un comando fallisce
trap 'echo "Errore: Installazione fallita alla linea $LINENO." >&2' ERR

# --- Variabili ---
# !!! IMPORTANTE: Sostituisci con l'URL del tuo repository GitHub
REPO_URL="https://github.com/Yul-1/SFT"
PROJECT_DIR="SFT" # La cartella dove verrà clonato il repo
PYTHON_CMD="python3"
VENV_DIR="venv"

# Colori per l'output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Avvio dell'installazione di AegisTransfer...${NC}"

# --- 1. Controllo Dipendenze di Sistema ---
echo -e "\n${YELLOW}1/5: Controllo delle dipendenze di sistema (apt)...${NC}"
DEPS=(git python3-dev python3-venv build-essential libssl-dev)
MISSING_DEPS=()

for dep in "${DEPS[@]}"; do
    if ! dpkg -l | grep -q "^ii.* $dep"; then
        MISSING_DEPS+=("$dep")
    fi
done

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo "Le seguenti dipendenze mancano: ${MISSING_DEPS[*]}"
    echo "È richiesta la password di sudo per installarle."
    sudo apt-get update
    sudo apt-get install -y "${MISSING_DEPS[@]}"
else
    echo "Tutte le dipendenze di sistema sono già installate."
fi

# --- 2. Download del Repository ---
if [ -d "$PROJECT_DIR" ]; then
    echo -e "\n${YELLOW}2/5: La cartella '$PROJECT_DIR' esiste già. Eseguo 'git pull'...${NC}"
    cd "$PROJECT_DIR"
    git pull
else
    if [ "$REPO_URL" == "https://github.com/Yul-1/SFT" ]; then
         echo -e "\n${RED}ERRORE: Modifica lo script 'install.sh' e imposta la variabile REPO_URL.${NC}"
         exit 1
    fi
    echo -e "\n${YELLOW}2/5: Download del repository da GitHub...${NC}"
    git clone "$REPO_URL" "$PROJECT_DIR"
    cd "$PROJECT_DIR"
fi

echo "Repository pronto in: $(pwd)"

# --- 3. Creazione e Attivazione Virtual Environment (venv) ---
echo -e "\n${YELLOW}3/5: Configurazione dell'ambiente virtuale Python...${NC}"
if [ ! -d "$VENV_DIR" ]; then
    $PYTHON_CMD -m venv "$VENV_DIR"
    echo "Ambiente virtuale creato."
else
    echo "Ambiente virtuale già esistente."
fi

# Attivazione Venv
source "$VENV_DIR/bin/activate"
echo "Ambiente virtuale attivato (python: $(which python))."

# --- 4. Installazione Dipendenze Python ---
echo -e "\n${YELLOW}4/5: Installazione dipendenze Python (pip)...${NC}"
# Come da documentazione (Guida alle Versioni), installiamo le dipendenze chiave.
# Se hai un file requirements.txt, sostituisci la linea seguente con:
# pip install -r requirements.txt
pip install --upgrade pip
pip install cryptography jsonschema setuptools

echo "Dipendenze Python installate."

# --- 5. Compilazione Modulo C (Crypto Accelerator) ---
echo -e "\n${YELLOW}5/5: Compilazione del modulo C 'crypto_accelerator'...${NC}"
# Usiamo la funzione di compilazione integrata nel wrapper,
# come previsto dalla versione 'main' del progetto.
$PYTHON_CMD python_wrapper_fixed.py --compile

if [ -f "crypto_accelerator.so" ]; then
    echo -e "\n${GREEN}=== Installazione Completata con Successo ===${NC}"
    echo "Il modulo C (crypto_accelerator.so) è stato compilato."
    echo "Per avviare il server, esegui:"
    echo -e "  ${YELLOW}cd $PROJECT_DIR${NC}"
    echo -e "  ${YELLOW}source $VENV_DIR/bin/activate${NC}"
    echo -e "  ${YELLOW}./secure_file_transfer_fixed.py --listen${NC}"
else
    echo -e "\n${RED}ERRORE: La compilazione del modulo C è fallita.${NC}"
    echo "Controlla l'output precedente per errori (es. header mancanti)."
    exit 1
fi#!/bin/bash