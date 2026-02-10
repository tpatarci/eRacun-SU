#!/bin/bash
# scripts/backup-claude-md.sh
DATE=$(date +%Y%m%d-%H%M%S)
cp CLAUDE.md "CLAUDE.md.backup-${DATE}"
echo "Backed up to CLAUDE.md.backup-${DATE}"
git add "CLAUDE.md.backup-${DATE}"
git commit -m "backup: CLAUDE.md before overhaul (${DATE})"
