# Phantom Files Daemon — Операционный Runbook

## Краткая справка

| Действие | Команда |
|----------|---------|
| Запуск демона | `systemctl start phantom` |
| Остановка демона | `systemctl stop phantom` |
| Перезагрузка конфига | `systemctl kill --signal=HUP phantom` |
| Проверка статуса | `systemctl status phantom` |
| Просмотр логов | `journalctl -u phantom -f` |
| Валидация конфига | `phantomctl validate` |
| Проверка продакшн-готовности | `phantomctl prod-check` |
| Начальная настройка | `sudo phantomctl bootstrap` |
| Смена режима | `sudo phantomctl mode set <active\|observation\|dry-run>` |

## Установка

### Из .deb пакета
```bash
sudo dpkg -i phantom-daemon_1.0.0_amd64.deb
sudo apt-get install -f  # установка зависимостей
```

### Из .rpm пакета
```bash
sudo rpm -i phantom-daemon-1.0.0.x86_64.rpm
```

### Из исходников
```bash
pip install -e .
sudo phantomctl bootstrap
```

## Первичная настройка

1. **Инициализация системы:**
   ```bash
   sudo phantomctl bootstrap
   ```
   Создаёт: пользователя/группу phantom, директории, RBAC-группы.

2. **Настройка секретов:**
   ```bash
   sudo vim /etc/phantom/secrets.env
   ```
   Обязательные переменные:
   - `PHANTOM_API_KEY` — API-ключ для аутентификации
   - `PHANTOM_JWT_SECRET` — ключ подписи JWT (минимум 32 символа)
   - `PHANTOM_TELEGRAM_BOT_TOKEN` — (опционально) бот Telegram
   - `PHANTOM_TELEGRAM_CHAT_ID` — (опционально) ID чата Telegram

3. **Валидация конфигурации:**
   ```bash
   phantomctl --config /etc/phantom/phantom.yaml validate
   ```

4. **Сборка образа песочницы (если `sandbox.enabled`):**
   ```bash
   make build-image
   ```
   Либо отключите песочницу в `config/phantom.yaml`, если Docker недоступен.

5. **Проверка готовности:**
   ```bash
   phantomctl prod-check
   ```

6. **Запуск демона:**
   ```bash
   sudo systemctl enable phantom
   sudo systemctl start phantom
   ```

## Режимы работы

| Режим | Поведение |
|-------|-----------|
| `active` | Полный ответ: изоляция, блокировка, завершение процессов |
| `observation` | Мониторинг + сбор форензики, без принудительных мер |
| `dry-run` | Только логирование, без принудительных мер |

Смена режима (требуются root-привилегии):
```bash
sudo phantomctl mode set observation
sudo systemctl kill --signal=HUP phantom  # применить без перезапуска
```

**Внимание:** Смена режима через API запрещена — только через CLI с root-привилегиями.

## Мониторинг

### Health-эндпоинт
```bash
curl http://127.0.0.1:8787/health
```

### Prometheus-метрики
```bash
curl http://127.0.0.1:8787/metrics
```

### Логи
```bash
# Логи в реальном времени
journalctl -u phantom -f

# Последние 100 строк
journalctl -u phantom -n 100

# Аудит-лог
tail -f /var/log/phantom/audit.jsonl

# Очередь ретраев алертов
tail -f /var/log/phantom/alert_queue.jsonl
```

## Реагирование на инциденты

### Просмотр инцидентов
```bash
curl -H "Authorization: Bearer $API_KEY" http://127.0.0.1:8787/api/v1/incidents
```

### Ручная блокировка IP
```bash
curl -X POST \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"kind": "ip", "targets": ["1.2.3.4"], "ttl_seconds": 3600}' \
  http://127.0.0.1:8787/api/v1/blocks
```

## Устранение неполадок

### Деградация сенсора
Если сенсор переключился на inotify:
1. Проверьте версию ядра: `uname -r` (нужно >= 5.10)
2. Проверьте capabilities: `getpcaps $(pidof phantomd)`
3. Проверьте доступность fanotify: `cat /proc/sys/fs/fanotify/max_user_marks`

### API не отвечает
1. Проверьте работу демона: `systemctl status phantom`
2. Проверьте привязку порта: `ss -tlnp | grep 8787`
3. Проверьте файрвол: `nft list ruleset`

### Проблемы с хранилищем улик
1. Проверьте место на диске: `df -h /var/lib/phantom`
2. Проверьте права: `ls -la /var/lib/phantom/evidence/`
3. Проверьте S3/MinIO (если включено): ошибки в логах
4. Если загрузки перестали идти после включения шифрования, проверьте `PHANTOM_EVIDENCE_KEY_B64` (fail-closed)

### Ошибки горячей перезагрузки
1. Проверьте доставку SIGHUP: `journalctl -u phantom | grep SIGHUP`
2. Валидируйте конфиг: `phantomctl validate`
3. Проверьте синтаксис YAML-файлов конфигурации

## Резервное копирование

### Создание бэкапа
```bash
# Конфигурация
tar czf phantom-config-$(date +%Y%m%d).tar.gz /etc/phantom/

# Улики
tar czf phantom-evidence-$(date +%Y%m%d).tar.gz /var/lib/phantom/evidence/
```

### Восстановление
```bash
tar xzf phantom-config-YYYYMMDD.tar.gz -C /
chown -R phantom:phantom /etc/phantom/
chmod 0600 /etc/phantom/phantom.yaml /etc/phantom/secrets.env
systemctl restart phantom
```

## Безопасность

- API слушает на `127.0.0.1` по умолчанию — используйте reverse proxy для внешнего доступа
- Всегда включайте TLS в продакшн (`api.tls_cert` / `api.tls_key` в конфиге)
- Периодически ротируйте API-ключи и JWT-секреты
- Улики зашифрованы AES-256-GCM и подписаны Ed25519
- Сбор env-переменных процессов выключен по умолчанию; включайте только с allowlist
- Правила nftables управляются Phantom — не изменяйте вручную
- Демон работает с минимальными capabilities: `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, `CAP_KILL`
