#!/bin/bash
set -e

# Остановка и отключение сервиса
if systemctl is-active --quiet phantom 2>/dev/null; then
    systemctl stop phantom
fi
if systemctl is-enabled --quiet phantom 2>/dev/null; then
    systemctl disable phantom
fi
