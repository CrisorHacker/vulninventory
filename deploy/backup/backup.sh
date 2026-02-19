#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/backup/data}"
DB_HOST="${DB_HOST:-db}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${POSTGRES_DB:-vuln_inventory}"
DB_USER="${POSTGRES_USER:-vulnuser}"
export PGPASSWORD="${POSTGRES_PASSWORD:-vulnpass}"

mkdir -p "$BACKUP_DIR"

STAMP=$(date +%Y%m%d_%H%M%S)
FILE="$BACKUP_DIR/vuln_inventory_${STAMP}.dump"

pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -F c "$DB_NAME" > "$FILE"

echo "Backup written to $FILE"
