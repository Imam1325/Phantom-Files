# Phantom Files — Справка по конфигурации

Конфиг по умолчанию: `config/phantom.yaml` (в проде обычно `/etc/phantom/phantom.yaml`).
Целевая среда: только Linux.

Относительные пути в `paths` резолвятся от корня проекта (директория с `pyproject.toml`), а не от текущего каталога.

## paths
- `logs_dir`: каталог логов (audit и alert queue JSONL).
- `traps_dir`: корневая директория ловушек.
- `evidence_dir`: локальное хранилище улик.
- `templates`: встроенные шаблоны.
- `user_templates_dir`: пользовательские шаблоны.
- `manifest`: путь к манифесту ловушек.
- `trap_registry_file`: файл реестра ловушек.
- `policies`: путь к политике реагирования.

## templates
- `globals`: key/value карта, подставляется в каждый рендеринг шаблона.
- `datasets`: список файлов данных (YAML/JSON). Загружаются по порядку и мерджатся в контекст шаблонов.

## sensors
- `driver`: `auto` | `ebpf` | `fanotify` | `inotify` (деградированный режим).
- `ebpf_enabled`: включить eBPF сенсоры.
- `ebpf_program`: путь к eBPF программе для файлового сенсора.
- `ebpf_poll_timeout_ms`: интервал опроса eBPF.
- `permission_timeout_ms`: таймаут fanotify permission.
- `whitelist_process_names`: список безопасных процессов.
- `ignore_paths`: паттерны исключаемых путей.
- `inotify_pid_lookup`: резолв PID через `lsof` в деградированном режиме (по умолчанию true).
- `inotify_pid_lookup_timeout`: таймаут `lsof` (сек).
- `inotify_pid_lookup_min_interval`: троттлинг между вызовами `lsof`.

## orchestrator
- `mode`: `active` | `observation` | `dry_run`.
- `worker_count`: число воркеров.
- `event_queue_size`: размер очереди событий.
- `event_dedup_window`: окно дедупликации (сек).
- `orient_timeout`: лимит анализа (сек).
- `act_timeout`: лимит исполнения действий (сек).
- `max_concurrent_actions`: лимит параллельных действий.
- `auto_execute`: автоисполнение действий.
- `min_severity`: минимальная серьёзность для действий.
- `fail_close`: deny по умолчанию при таймаутах.
- `degraded_timeout_block`: немедленное сдерживание в деградации.
- `block_ttl_seconds`: TTL для изоляции процесса.
- `ip_block_ttl_seconds`: TTL для IP блокировок.

## forensics
- `timeout_seconds`: лимит времени на сбор улик.
- `memory_dump`: включить дамп памяти.
- `chain_state_file`: путь к файлу цепочки целостности.
- `s3.enabled`: включить выгрузку в S3/MinIO.
- `s3.endpoint_url`: endpoint S3/MinIO.
- `s3.region`: регион S3.
- `s3.bucket`: имя bucket.
- `s3.prefix`: префикс объектов.
- `s3.access_key_env`: env var с access key.
- `s3.secret_key_env`: env var с secret key.
- `s3.encryption_key_env`: base64 env var ключа AES-256-GCM (после декодирования 32 байта). При ошибке загрузка улик прекращается (fail-closed).
- `s3.verify_tls`: проверка TLS.
- `s3.object_lock_days`: дни удержания Object Lock.
- `s3.upload_timeout_seconds`: таймаут загрузки.
- `pcap_precapture.enabled`: пред/пост захват пакетов.
- `pcap_precapture.interface`: интерфейс (пусто = авто).
- `pcap_precapture.ebpf_program`: путь к eBPF программе.
- `pcap_precapture.max_buffer_mb`: размер буфера.
- `pcap_precapture.min_memory_mb_for_precapture`: минимум RAM.
- `pcap_precapture.pre_seconds`: секунд до события.
- `pcap_precapture.post_seconds`: секунд после события.
- `pcap_precapture.snaplen`: длина пакета.
- `pcap_precapture.capture_ports`: список портов фильтра.

## telemetry
- `process.collect_env`: сбор env-переменных (по умолчанию выключен).
- `process.env_allowlist`: allowlist ключей env.
- `process.env_denylist`: denylist ключей env (перебивает allowlist).
- `process.max_env_entries`: лимит количества переменных.
- `process.max_env_value_len`: лимит длины значения (обрезка с `...`).

## signing
- `ed25519_private_key_path`: путь к приватному ключу Ed25519.
- `ed25519_passphrase_env`: env var с passphrase.

## api
- `enabled`: включить API сервер.
- `bind`: адрес bind.
- `port`: порт.
- `security_mode`: `api_key` | `jwt` | `both` | `mtls`.
- `api_key_env`: env var API key.
- `keys`: список `{env, role}` для RBAC.
- `rate_limit_per_minute`: лимит запросов на IP.
- `tls_cert`: путь к TLS сертификату.
- `tls_key`: путь к TLS ключу.

## integrations
- `webhook_urls`: webhook endpoints.
- `syslog_enabled`: включить syslog экспорт.
- `syslog_address`: путь сокета или host/port.
- `telegram_enabled`: включить Telegram.
- `telegram_bot_token_env`: env var токена бота.
- `telegram_chat_id_env`: env var id чата.

## rotation
- `enabled`: включить ротацию ловушек.
- `interval_seconds`: интервал ротации.
- `batch_size`: размер батча.
- `min_age_seconds`: минимальный возраст файла.

## enforcement
- `allow_uid_fallback`: разрешить UID-level изоляцию при падении cgroup eBPF (по умолчанию выключено).

## sandbox
- `enabled`: включить запуск песочницы в forensics (в примере включено).
- `image`: Docker образ песочницы.
- `command`: команда внутри контейнера.
- `timeout_seconds`: таймаут песочницы.
- `network_disabled`: отключение сети.
- `container_prefix`: префикс контейнеров.
