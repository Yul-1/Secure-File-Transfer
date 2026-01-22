#!/bin/bash
# SFT Docker aliases

alias sft-build='docker build -t sft-rust:alpine .'
alias sft-up='docker compose up -d'
alias sft-down='docker compose down'
alias sft-logs='docker logs -f sft-server'
alias sft-shell='docker exec -it sft-server sh'
alias sft-restart='docker restart sft-server'
alias sft-ps='docker ps | grep sft'
alias sft-clean='docker system prune -f'

# Server rapido
alias sft-start='docker run -d --name sft-server -p 5555:5555 -v $(pwd)/data:/app/files sft-rust:alpine'
alias sft-stop='docker stop sft-server && docker rm sft-server'

# Robust SFT Client (Auto-Resolve IP)
sft-client() {
    if [ "$#" -ne 2 ]; then
        echo "Error: Usage: sft-client <local_file_path> <host:port>"
        return 1
    fi

    local local_file="$1"
    local target="$2"

    if [ ! -f "$local_file" ]; then
        echo "Error: File '$local_file' does not exist."
        return 1
    fi

    local abs_path=$(realpath "$local_file")
    local filename=$(basename "$local_file")
    local network="rust_default"

    # Se il target è "sft-server", risolve automaticamente IP e Rete
    if [[ "$target" == "sft-server:"* ]]; then
        local port="${target#*:}"
        local server_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' sft-server 2>/dev/null)
        network=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' sft-server 2>/dev/null)
        
        if [ -z "$server_ip" ]; then
            echo "Error: sft-server is not running."
            return 1
        fi
        
        target="$server_ip:$port"
        echo "Auto-detected server at $target on network '$network'"
    fi

    echo "Sending '$filename' to '$target'..."

    docker run --rm --network "$network" \
        -v "$abs_path:/app/ricevuti/$filename:ro" \
        sft-rust:alpine python3 sft.py --mode client \
        --connect "$target" --file "/app/ricevuti/$filename"
}

echo "✅ SFT aliases loaded"
echo "Usage: sft-build | sft-up | sft-logs | sft-send file.txt host:5555"
