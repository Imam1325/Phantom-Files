#!/bin/bash
set -e

# Создание системного пользователя и группы phantom
if ! getent group phantom >/dev/null 2>&1; then
    groupadd --system phantom
fi

if ! getent passwd phantom >/dev/null 2>&1; then
    useradd --system \
        --gid phantom \
        --shell /usr/sbin/nologin \
        --home-dir /var/lib/phantom \
        --no-create-home \
        --comment "Phantom Files Daemon" \
        phantom
fi

# Группы для RBAC
for grp in phantom-admin phantom-editor phantom-user; do
    if ! getent group "$grp" >/dev/null 2>&1; then
        groupadd --system "$grp"
    fi
done
