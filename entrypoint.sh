#!/bin/bash
set -e

case "$RUN_MODE" in
    trading)
        echo "Starting SilverVeil Trading Terminal (silverveil_trading.py)"
        exec python silverveil_trading.py
        ;;
    backend)
        echo "Starting Legacy Backend (silverveil_backend.py)"
        exec python silverveil_backend.py
        ;;
    signer)
        echo "Starting Signer Service (signer_service.py)"
        exec python signer_service.py
        ;;
    supervisor)
        echo "Starting all services via supervisord (signer + trading)"
        exec supervisord -c supervisord.conf
        ;;
    *)
        echo "Unknown RUN_MODE=$RUN_MODE. Defaulting to supervisor."
        exec supervisord -c supervisord.conf
        ;;
esac