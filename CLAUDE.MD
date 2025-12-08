# Claude Code - Istruzioni di Progetto

Questo file contiene le linee guida da seguire per tutte le sessioni di sviluppo del progetto SFT (Secure File Transfer).

## Regole di Codifica

### Commenti al Codice
- Commentare cosa fanno i vari pezzi di codice
- Essere molto concisi e brevi
- NON usare parole come: fix, solution, modified, issue, bug, patch, etc.
- Descrivere solo la funzionalità, non il motivo della modifica

### Stile
- NON usare mai emoji in nessun file o commit
- NON mettere mai firma o nome (Claude, Anthropic, etc.) nel codice o commit
- Seguire lo stile esistente del progetto

## Gestione Versioni

### Versioning Indipendente
- Ogni implementazione (C, RUST, Windows) ha versioning indipendente
- Aggiornare la versione in tutti i file rilevanti quando si fa una release
- Mantenere sincronizzate le versioni major/minor tra implementazioni per feature comuni

### Session Log
- Dopo ogni sessione, aggiornare il SESSION_LOG.md delle versioni modificate
- Documentare: data, file modificati, summary conciso delle modifiche
- Non creare session log se non ci sono state modifiche a quella versione

## Documentazione

### README
- Mantenere i README aggiornati e fedeli allo stato del progetto
- Aggiornare version badges, feature lists, installation steps quando cambiano
- Ogni implementazione (C/, RUST/, Windows/) ha il proprio README
- Il README root documenta l'overview del progetto multi-implementazione

### Documentazione Aggiuntiva
- NON creare altra documentazione se non esplicitamente richiesto
- Non creare file come CHANGELOG.md, CONTRIBUTING.md, etc. a meno che richiesto
- Preferire documentazione inline (docstrings, commenti) a file separati

## Workflow Git

### Commit
- Messaggi di commit chiari e concisi
- NON usare emoji nei commit messages
- NON aggiungere firma "Co-Authored-By: Claude" o simili
- Seguire conventional commits quando possibile: type(scope): description

### Branch Management
- NON fare mai merge di branch se non richiesto esplicitamente dall'utente
- Lavorare sul branch corrente salvo indicazioni diverse
- Non creare branch automaticamente

### File Tracking
- Rispettare il .gitignore esistente
- Non committare file temporanei, build artifacts, logs
- Non committare questo file (CLAUDE.MD è in .gitignore)
- NON cancellare mai file non tracciati da git o presenti in .gitignore
- Non rimuovere build artifacts, logs, file temporanei dell'utente
- Lasciare intatti tutti i file ignorati da git salvo esplicita richiesta

## Sicurezza

### Testing
- Dopo modifiche di sicurezza, eseguire i test di penetrazione se disponibili
- Documentare i risultati nel report appropriato

### Dependency Updates
- Verificare compatibilità prima di aggiornare dipendenze
- Documentare il motivo degli aggiornamenti nel session log

## Note Implementazione

### C Implementation
- Usa OpenSSL per operazioni crittografiche
- Modulo C: crypto_accelerator.c
- X25519/Ed25519: libreria Python cryptography

### RUST Implementation
- Usa crate Rust pure (dalek, aes-gcm)
- Modulo Rust: crypto_accelerator (via maturin)
- X25519/Ed25519: implementazione Rust nativa

### Windows Implementation
- Package del modulo RUST per Windows
- Installer: Inno Setup
- Include Python embedded runtime

---

Queste linee guida devono essere seguite in ogni sessione di lavoro su questo progetto.
