#!/bin/bash
set -e

# Установка Python-зависимостей
if command -v pip3 >/dev/null 2>&1; then
    pip3 install --quiet \
        watchdog PyYAML Faker Jinja2 psutil cryptography \
        boto3 starlette uvicorn prometheus-client PyJWT \
        2>/dev/null || true
fi

# Установка прав на директории
chown -R phantom:phantom /var/lib/phantom /var/log/phantom /etc/phantom
chmod 0750 /var/lib/phantom /var/log/phantom
chmod 0700 /var/lib/phantom/evidence 2>/dev/null || true
chmod 0600 /etc/phantom/phantom.yaml /etc/phantom/policies.yaml 2>/dev/null || true

# Создание secrets.env если не существует
if [ ! -f /etc/phantom/secrets.env ]; then
    cat > /etc/phantom/secrets.env <<'EOF'
# Phantom secrets (заполните перед запуском)
# PHANTOM_API_KEY=your-api-key-here
# PHANTOM_JWT_SECRET=your-jwt-secret-min-32-chars-here
# PHANTOM_TELEGRAM_BOT_TOKEN=
# PHANTOM_TELEGRAM_CHAT_ID=
EOF
    chown phantom:phantom /etc/phantom/secrets.env
    chmod 0600 /etc/phantom/secrets.env
fi

# Перезагрузка systemd
systemctl daemon-reload
echo "Phantom Files Daemon v1.0.0 установлен."
echo "Настройте /etc/phantom/secrets.env и запустите: systemctl start phantom"
