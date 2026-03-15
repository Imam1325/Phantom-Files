"""
Phantom Daemon — Configuration Module

Отвечает за загрузку, валидацию и предоставление конфигурации системе.

Design Principles:
  - Strict Separation: Возвращает только dict/primitives. Не импортирует бизнес-логику.
  - Fail-Fast: Валидация на старте, не в runtime.
  - 12-Factor App: ENV overrides, профили окружения.
  - Security-First: Проверка прав доступа, размеров, injection-safe.
  - Immutable: Конфиг кэшируется и не мутируется после загрузки.

Thread Safety:
  - Singleton pattern с thread-safe initialization.
  - Все dict'ы глубоко замораживаются после загрузки.

Performance:
  - Lazy loading: конфиг загружается только при первом обращении.
  - Env override optimization: deepcopy только если есть overrides.
  - Path resolution caching.
"""

from __future__ import annotations

import os
import re
import sys
import logging
import threading
from collections.abc import Mapping
from typing import Any, Dict, Optional, Set, Final
from pathlib import Path
from types import MappingProxyType

# YAML — обязательная зависимость
try:
    import yaml
except ImportError:
    raise ImportError(
        "PyYAML is required. Install via 'pip install pyyaml' or "
        "'pip install phantom-daemon[config]'"
    )

# =============================================================================
# LOGGING
# =============================================================================

logger = logging.getLogger("phantom.config")


# =============================================================================
# EXCEPTIONS
# =============================================================================

class ConfigError(Exception):
    """Базовое исключение для ошибок конфигурации."""
    
    def __init__(self, message: str, path: Optional[str] = None, key: Optional[str] = None):
        self.path = path
        self.key = key
        super().__init__(message)


# =============================================================================
# CONSTANTS
# =============================================================================

# Автоопределение корня проекта
# Эвристика: ищем pyproject.toml вверх по дереву (до 5 уровней)
def _find_project_root() -> Path:
    """Находит корень проекта по наличию pyproject.toml."""
    current = Path(__file__).resolve().parent
    for _ in range(5):
        if (current / "pyproject.toml").exists():
            return current
        if current == current.parent:  # Достигли filesystem root
            break
        current = current.parent
    
    # Fallback: используем cwd (но предупреждаем)
    logger.debug("pyproject.toml not found, using cwd as project root")
    return Path.cwd()

PROJECT_ROOT: Final[Path] = _find_project_root()

# Security limits
MAX_CONFIG_SIZE: Final[int] = 2 * 1024 * 1024  # 2 MB (увеличен для больших конфигов)
SAFE_FILE_PERMISSIONS: Final[int] = 0o600  # Owner read/write only

# Schema definition
REQUIRED_SECTIONS: Final[Set[str]] = {"paths"}
OPTIONAL_SECTIONS: Final[Set[str]] = {
    "sensors",
    "orchestrator",
    "response",
    "sandbox",
    "logging",
    "forensics",
    "signing",
    "api",
    "integrations",
    "templates",
}

# Известные пути (для валидации и предупреждений)
KNOWN_PATHS: Final[Set[str]] = {
    "logs_dir",
    "traps_dir",
    "data_dir",
    "evidence_dir",
    "manifest",
    "templates",
    "user_templates_dir",
    "trap_registry_file",
    "audit_trail_file",
    "policies",
}

REQUIRED_PATHS: Final[Set[str]] = {"logs_dir", "traps_dir"}

# ENV overrides
ENV_PREFIX: Final[str] = "PHANTOM_"
ENV_VAR_PATTERN: Final[re.Pattern] = re.compile(r'\$\{([^}:]+)(?::([^}]+))?\}')

# Профили окружения (PHANTOM_PROFILE=production)
DEFAULT_PROFILE: Final[str] = "default"

# =============================================================================
# GLOBAL STATE (Thread-Safe Singleton)
# =============================================================================

_CONFIG_CACHE: Optional[MappingProxyType] = None
_CONFIG_LOCK = threading.Lock()
_PATH_CACHE: Dict[str, str] = {}


# =============================================================================
# PUBLIC API
# =============================================================================

def get_config(
    path: Optional[str] = None,
    profile: Optional[str] = None,
    reload: bool = False
) -> MappingProxyType:
    """
    Получает конфигурацию (Thread-Safe Singleton).
    
    Args:
        path: Путь к файлу конфигурации. Если None, ищется автоматически.
        profile: Профиль окружения (default/dev/prod). Если None, читается из PHANTOM_PROFILE.
        reload: Если True, принудительно перезагружает конфиг (для тестов).
    
    Returns:
        Неизменяемый словарь с конфигурацией (MappingProxyType).
    
    Raises:
        ConfigError: При ошибках загрузки, валидации или I/O.
    
    Thread Safety:
        Первый вызов блокирует через threading.Lock.
        Последующие вызовы возвращают кэшированный объект без блокировки.
    """
    global _CONFIG_CACHE
    
    # Fast path: уже загружен и не требуется reload
    if _CONFIG_CACHE is not None and not reload:
        return _CONFIG_CACHE
    
    # Slow path: загрузка с блокировкой
    with _CONFIG_LOCK:
        # Double-check внутри lock (другой поток мог загрузить)
        if _CONFIG_CACHE is not None and not reload:
            return _CONFIG_CACHE
        if reload:
            _PATH_CACHE.clear()
        
        if path is None:
            path = _get_default_config_path()
        
        if profile is None:
            profile = os.getenv("PHANTOM_PROFILE", DEFAULT_PROFILE)
        
        logger.info(f"Loading configuration from {path} (profile: {profile})")
        
        raw_config = _load_and_process_config(path)
        final_config = _apply_profile(raw_config, profile)
        
        # Глубокое замораживание для immutability
        _CONFIG_CACHE = _deep_freeze(final_config)
        
        return _CONFIG_CACHE


def get_path(name: str, *, ensure_exists: bool = True, ensure_writable: bool = True) -> str:
    """
    Безопасное получение абсолютного пути из конфигурации.
    
    Особенности:
      - Резолвит относительные пути от PROJECT_ROOT.
      - Поддерживает ~ (home directory).
      - Кэширует результаты для performance.
      - Создаёт директории для *_dir ключей.
      - Проверяет права записи для критичных путей.
    
    Args:
        name: Имя пути из секции 'paths'.
        ensure_exists: Если True, создаёт директорию (для *_dir).
        ensure_writable: Если True, проверяет права записи.
    
    Returns:
        Абсолютный путь (строка).
    
    Raises:
        ConfigError: Если путь не найден, недоступен или не writable.
    
    Examples:
        >>> get_path("logs_dir")
        '/var/log/phantom'
        >>> get_path("manifest", ensure_writable=False)
        '/etc/phantom/traps_manifest.yaml'
    """
    # Cache lookup (thread-safe за счёт GIL для dict reads)
    cache_key = f"{name}:{ensure_exists}:{ensure_writable}"
    if cache_key in _PATH_CACHE:
        return _PATH_CACHE[cache_key]
    
    config = get_config()
    paths = config.get("paths", {})
    
    if name not in paths:
        raise ConfigError(
            f"Path '{name}' not found in configuration",
            key=f"paths.{name}"
        )
    
    raw_path = paths[name]
    
    if not isinstance(raw_path, str):
        raise ConfigError(
            f"Path '{name}' must be a string, got {type(raw_path).__name__}",
            key=f"paths.{name}"
        )
    
    # Resolve path
    path_obj = Path(raw_path)
    
    # Handle ~ expansion
    if raw_path.startswith("~/"):
        path_obj = Path(os.path.expanduser(raw_path))
    
    # Resolve relative paths from PROJECT_ROOT
    if not path_obj.is_absolute():
        path_obj = PROJECT_ROOT / path_obj
    
    final_path = path_obj.resolve()
    
    # Heuristic: создаём директории для ключей, оканчивающихся на _dir или templates
    is_directory = name.endswith("_dir") or name in ("templates",)
    
    if is_directory and ensure_exists:
        try:
            final_path.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise ConfigError(
                f"Cannot create directory {final_path}: {e}. "
                "Check permissions or adjust configuration.",
                path=str(final_path)
            )
    
    # Write access check (для критичных директорий)
    if is_directory and ensure_writable:
        if not os.access(final_path, os.W_OK):
            raise ConfigError(
                f"Directory {final_path} is not writable by current user (UID {os.getuid()}). "
                "Run daemon with appropriate permissions or change configuration.",
                path=str(final_path)
            )
    
    result = str(final_path)
    _PATH_CACHE[cache_key] = result
    return result


def validate_config_for_daemon() -> None:
    """
    Выполняет комплексную проверку конфигурации перед запуском демона.
    
    Проверяет:
      - Все обязательные пути существуют и доступны для записи.
      - Секции orchestrator, sensors присутствуют (если не dev mode).
      - Численные параметры в допустимых пределах.
    
    Raises:
        ConfigError: При обнаружении проблем.
    
    Usage:
        # В daemon.py перед daemonize()
        try:
            validate_config_for_daemon()
        except ConfigError as e:
            logger.error(f"Configuration error: {e}")
            sys.exit(1)
    """
    config = get_config()
    
    # 1. Проверка обязательных секций для daemon mode
    if os.getenv("PHANTOM_MODE") != "dev":
        required_for_daemon = {"orchestrator", "sensors"}
        missing = required_for_daemon - config.keys()
        if missing:
            raise ConfigError(
                f"Daemon mode requires sections: {', '.join(missing)}. "
                "Add them to config or set PHANTOM_MODE=dev for testing."
            )
    
    # 2. Проверка критичных путей
    for path_name in REQUIRED_PATHS:
        try:
            # ensure_writable=True поднимет ConfigError если нет прав
            get_path(path_name, ensure_exists=True, ensure_writable=True)
        except ConfigError as e:
            raise ConfigError(
                f"Critical path '{path_name}' validation failed: {e}",
                key=f"paths.{path_name}"
            )

    # Optional but operationally required files in v2
    optional_files = ("manifest", "templates", "policies")
    for name in optional_files:
        if name not in config.get("paths", {}):
            continue
        value = config["paths"][name]
        if not isinstance(value, str) or not value.strip():
            raise ConfigError(f"paths.{name} must be non-empty string", key=f"paths.{name}")

    if "sensors" in config:
        sensors = config["sensors"]
        driver = str(sensors.get("driver", "auto")).lower()
        if driver not in {"auto", "fanotify", "inotify", "ebpf"}:
            raise ConfigError(
                f"sensors.driver must be one of auto|fanotify|inotify|ebpf, got {driver}",
                key="sensors.driver",
            )
        if "permission_timeout_ms" in sensors:
            timeout_ms = sensors["permission_timeout_ms"]
            if not isinstance(timeout_ms, int) or timeout_ms < 1 or timeout_ms > 5000:
                raise ConfigError(
                    "sensors.permission_timeout_ms must be in range 1..5000",
                    key="sensors.permission_timeout_ms",
                )

    if "forensics" in config:
        forensics = config["forensics"]
        s3_cfg = forensics.get("s3", {})
        if isinstance(s3_cfg, dict) and bool(s3_cfg.get("enabled", False)):
            bucket = str(s3_cfg.get("bucket", "")).strip()
            if not bucket:
                raise ConfigError(
                    "forensics.s3.bucket must be set when forensics.s3.enabled=true",
                    key="forensics.s3.bucket",
                )
            lock_days = s3_cfg.get("object_lock_days", 90)
            if not isinstance(lock_days, int) or lock_days < 0:
                raise ConfigError(
                    "forensics.s3.object_lock_days must be >= 0",
                    key="forensics.s3.object_lock_days",
                )
        pcap_cfg = forensics.get("pcap_precapture", {})
        if isinstance(pcap_cfg, dict):
            if "max_buffer_mb" in pcap_cfg:
                mb = pcap_cfg["max_buffer_mb"]
                if not isinstance(mb, int) or mb < 8 or mb > 256:
                    raise ConfigError(
                        "forensics.pcap_precapture.max_buffer_mb must be in range 8..256",
                        key="forensics.pcap_precapture.max_buffer_mb",
                    )
            if "min_memory_mb_for_precapture" in pcap_cfg:
                mem = pcap_cfg["min_memory_mb_for_precapture"]
                if not isinstance(mem, int) or mem < 128:
                    raise ConfigError(
                        "forensics.pcap_precapture.min_memory_mb_for_precapture must be >= 128",
                        key="forensics.pcap_precapture.min_memory_mb_for_precapture",
                    )

    if "templates" in config:
        templates = config["templates"]
        if not isinstance(templates, Mapping):
            raise ConfigError("templates section must be a mapping", key="templates")
        globals_data = templates.get("globals", templates.get("global_vars", {}))
        if globals_data is not None and not isinstance(globals_data, Mapping):
            raise ConfigError("templates.globals must be a mapping", key="templates.globals")
        datasets = templates.get("datasets", [])
        if datasets is not None:
            if not isinstance(datasets, (list, tuple)):
                raise ConfigError("templates.datasets must be a list", key="templates.datasets")
            for idx, item in enumerate(datasets):
                if not isinstance(item, str) or not item.strip():
                    raise ConfigError(
                        f"templates.datasets[{idx}] must be a non-empty string path",
                        key="templates.datasets",
                    )
    
    # 3. Валидация численных параметров orchestrator (если есть)
    if "orchestrator" in config:
        orch = config["orchestrator"]
        
        if "worker_count" in orch:
            val = orch["worker_count"]
            if not isinstance(val, int) or not 1 <= val <= 128:
                raise ConfigError(
                    f"orchestrator.worker_count must be 1-128, got {val}",
                    key="orchestrator.worker_count"
                )
        
        if "event_queue_size" in orch:
            val = orch["event_queue_size"]
            if not isinstance(val, int) or val < 100:
                raise ConfigError(
                    f"orchestrator.event_queue_size must be >= 100, got {val}",
                    key="orchestrator.event_queue_size"
                )
        if "mode" in orch:
            mode = str(orch["mode"]).lower()
            if mode not in {"active", "observation", "dry_run", "dry-run"}:
                raise ConfigError(
                    f"orchestrator.mode must be one of active|observation|dry_run, got {mode}",
                    key="orchestrator.mode",
                )
        for ttl_key in ("block_ttl_seconds", "ip_block_ttl_seconds"):
            if ttl_key in orch and orch[ttl_key] is not None:
                try:
                    ttl_val = int(orch[ttl_key])
                except Exception:
                    raise ConfigError(
                        f"orchestrator.{ttl_key} must be integer or null",
                        key=f"orchestrator.{ttl_key}",
                    )
                if ttl_val < 0:
                    raise ConfigError(
                        f"orchestrator.{ttl_key} must be >= 0",
                        key=f"orchestrator.{ttl_key}",
                    )
    
    logger.info("Configuration validation passed ✓")


def get_profile() -> str:
    """Возвращает текущий активный профиль конфигурации."""
    return os.getenv("PHANTOM_PROFILE", DEFAULT_PROFILE)


def clear_cache() -> None:
    """
    Очищает кэш конфигурации и путей.
    
    Полезно для тестов и hot-reload в dev mode.
    Thread-safe.
    """
    global _CONFIG_CACHE
    with _CONFIG_LOCK:
        _CONFIG_CACHE = None
        _PATH_CACHE.clear()
        logger.debug("Configuration cache cleared")


# =============================================================================
# INTERNAL: CONFIG LOADING
# =============================================================================

def _get_default_config_path() -> str:
    """
    Определяет путь к конфигу с чётким приоритетом.
    
    Приоритет (по убыванию):
      1. PHANTOM_CONFIG_PATH environment variable
      2. ./config/phantom.yaml (относительно PROJECT_ROOT)
      3. /etc/phantom/phantom.yaml (system-wide Linux)
      4. Fallback: ./config/phantom.yaml (даже если не существует)
    """
    # 1. ENV variable (highest priority)
    env_path = os.getenv("PHANTOM_CONFIG_PATH")
    if env_path:
        return env_path
    
    # 2. Project-local config (dev mode)
    dev_path = PROJECT_ROOT / "config" / "phantom.yaml"
    if dev_path.exists():
        return str(dev_path)
    
    # 3. System-wide configs (production)
    for sys_path in [
        Path("/etc/phantom/phantom.yaml"),
    ]:
        if sys_path.exists():
            return str(sys_path)
    
    # 4. Fallback (will fail later with clear error)
    return str(dev_path)


def _load_and_process_config(path: str) -> Dict[str, Any]:
    """
    Загружает конфиг из файла и применяет все трансформации.
    
    Pipeline:
      1. Security checks (size, permissions)
      2. YAML parsing
      3. Variable expansion (${VAR})
      4. ENV overrides (PHANTOM_*)
      5. Validation
    """
    # 1. Existence check
    if not os.path.exists(path):
        raise ConfigError(f"Configuration file not found: {path}", path=path)
    
    # 2. Security checks
    _check_file_security(path)
    
    # 3. Load YAML
    try:
        with open(path, "rt", encoding="utf-8") as f:
            raw_config = yaml.safe_load(f)
    except OSError as e:
        raise ConfigError(f"Cannot read config file: {e}", path=path)
    except yaml.YAMLError as e:
        raise ConfigError(f"Invalid YAML syntax: {e}", path=path)
    
    if not isinstance(raw_config, dict):
        raise ConfigError(
            f"Configuration root must be a dictionary, got {type(raw_config).__name__}",
            path=path
        )
    
    # 4. Variable expansion
    expanded = _recursive_expand_vars(raw_config)
    
    # 5. ENV overrides
    final = _apply_env_overrides(expanded)
    
    # 6. Validation
    _validate_structure(final, path)
    
    return final


def _check_file_security(path: str) -> None:
    """
    Проверяет безопасность конфигурационного файла.
    
    Security checks:
      - File size (DoS protection)
      - Ownership (не должен принадлежать другому юзеру кроме root)
      - Permissions (не должен быть world-writable, желательно 0600)
    
    Все проверки — warnings, не errors (для гибкости в dev).
    """
    try:
        stat = os.stat(path)
    except OSError as e:
        raise ConfigError(f"Cannot stat config file: {e}", path=path)
    
    # Size check (hard limit)
    if stat.st_size > MAX_CONFIG_SIZE:
        raise ConfigError(
            f"Config file too large: {stat.st_size} bytes (max {MAX_CONFIG_SIZE})",
            path=path
        )
    
    current_uid = os.getuid()
    
    # Ownership check
    if stat.st_uid not in (current_uid, 0):
        logger.warning(
            f"Config file {path} is owned by UID {stat.st_uid}, "
            f"not current user ({current_uid}) or root (0). "
            "This may be a security risk if the file is writable by others."
        )
    
    # Permissions check
    mode = stat.st_mode
    
    # Critical: world-writable (anyone can modify)
    if mode & 0o002:
        logger.error(
            f"CRITICAL: Config file {path} is world-writable (permissions: {oct(mode)[-3:]}). "
            "This is a severe security risk. Recommended: chmod 600"
        )
    
    # Warning: group/world readable (может содержать credentials)
    if mode & 0o044:
        logger.warning(
            f"Config file {path} has permissions {oct(mode)[-3:]}. "
            "Recommended: 0600 (owner read/write only) for security."
        )


# =============================================================================
# INTERNAL: VARIABLE EXPANSION
# =============================================================================

def _expand_value(value: Any) -> Any:
    """
    Раскрывает переменные окружения в строках.
    
    Supported formats:
      - ${VAR} — обязательная переменная (оставляет как есть если не найдена)
      - ${VAR:default} — опциональная с дефолтом
      - ~/path — home directory expansion
    
    Security:
      - Не выполняет shell expansion (безопасно от injection).
      - Не интерпретирует специальные символы.
    """
    if not isinstance(value, str):
        return value
    
    # Home directory expansion
    if value.startswith("~/"):
        value = os.path.expanduser(value)
    
    # Environment variable substitution
    def replace_match(match: re.Match) -> str:
        var_name = match.group(1)
        default_val = match.group(2)
        
        env_val = os.getenv(var_name)
        if env_val is not None:
            return env_val
        if default_val is not None:
            return default_val
        
        # Переменная не найдена — оставляем как есть (видно пользователю)
        return match.group(0)
    
    return ENV_VAR_PATTERN.sub(replace_match, value)


def _recursive_expand_vars(data: Any) -> Any:
    """Рекурсивно обходит структуру и применяет _expand_value."""
    if isinstance(data, dict):
        return {k: _recursive_expand_vars(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [_recursive_expand_vars(v) for v in data]
    else:
        return _expand_value(data)


# =============================================================================
# INTERNAL: ENV OVERRIDES
# =============================================================================

def _apply_env_overrides(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Применяет 12-factor style overrides из переменных окружения.
    
    Format: PHANTOM_SECTION__KEY__SUBKEY=value
    Example: PHANTOM_ORCHESTRATOR__WORKER_COUNT=8
    
    Type inference:
      - "true"/"false" → bool
      - "123" → int
      - "1.5" → float
      - остальное → str
    
    Optimization:
      Deepcopy происходит только если есть хотя бы один override.
    """
    # Fast path: проверяем наличие overrides до дорогого deepcopy
    has_overrides = any(k.startswith(ENV_PREFIX) for k in os.environ)
    if not has_overrides:
        return config
    
    # Slow path: копируем и применяем
    import copy
    new_config = copy.deepcopy(config)
    
    # Мета-переменные, не являющиеся config-overrides
    _EXCLUDED_EXACT = {
        "CONFIG_PATH", "PROFILE", "MODE",
    }
    _EXCLUDED_PREFIXES = {
        "API_KEY",
        "SIGNING_PASSPHRASE",
        "S3_ACCESS_KEY",
        "S3_SECRET_KEY",
        "EVIDENCE_KEY_B64",
        "JWT_SECRET",
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_CHAT_ID",
    }

    for env_key, env_val in os.environ.items():
        if not env_key.startswith(ENV_PREFIX):
            continue

        # Parse key path
        trimmed = env_key[len(ENV_PREFIX):]

        if trimmed in _EXCLUDED_EXACT or any(trimmed.startswith(prefix) for prefix in _EXCLUDED_PREFIXES):
            continue

        parts = trimmed.split("__")
        
        if not parts:
            continue
        
        # Normalize to lowercase (YAML keys обычно lowercase)
        path_keys = [p.lower() for p in parts]
        
        # Infer type
        typed_val = _infer_type(env_val)
        
        # Set nested value
        _set_nested_value(new_config, path_keys, typed_val)
        
        logger.debug(f"Applied ENV override: {'.'.join(path_keys)}")
    
    return new_config


def _infer_type(value: str) -> Any:
    """
    Угадывает тип значения из строки ENV.

    Rules:
      - Boolean: true/yes/on → True, false/no/off → False (case-insensitive)
      - Integer: "123" → 123, "0" → 0, "1" → 1 (если парсится без ошибки)
      - Float: "1.5" → 1.5 (если парсится без ошибки)
      - String: остальное
    """
    lower = value.lower()
    
    # Boolean
    if lower in ("true", "yes", "on"):
        return True
    if lower in ("false", "no", "off"):
        return False
    
    # Integer
    try:
        return int(value)
    except ValueError:
        pass
    
    # Float
    try:
        return float(value)
    except ValueError:
        pass
    
    # String (default)
    return value


def _set_nested_value(config: Dict[str, Any], keys: list[str], value: Any) -> None:
    """
    Безопасно устанавливает значение во вложенном словаре.
    
    Создаёт промежуточные dict'ы если они отсутствуют.
    Игнорирует если на пути встретился не-dict (с warning).
    """
    current = config
    
    for key in keys[:-1]:
        if key not in current:
            current[key] = {}
        
        if not isinstance(current[key], dict):
            logger.warning(
                f"ENV override failed: '{key}' is not a dict (path: {'.'.join(keys)})"
            )
            return
        
        current = current[key]
    
    current[keys[-1]] = value


# =============================================================================
# INTERNAL: PROFILE SUPPORT
# =============================================================================

def _apply_profile(config: Dict[str, Any], profile: str) -> Dict[str, Any]:
    """
    Применяет профиль окружения (dev/prod/staging).
    
    Format в YAML:
      default:
        orchestrator:
          worker_count: 4
      
      production:
        orchestrator:
          worker_count: 16
        logging:
          level: WARNING
    
    Логика:
      1. Берём секцию "default" (если есть) как базу.
      2. Мерджим с секцией <profile> (глубокий merge).
      3. Удаляем служебные ключи (default, production, etc).
    
    Args:
        config: Raw конфиг из YAML.
        profile: Имя профиля (default/production/dev/staging).
    
    Returns:
        Конфиг с применённым профилем.
    """
    # Если профилей нет в конфиге — возвращаем как есть
    if profile not in config and DEFAULT_PROFILE not in config:
        return config
    
    # Начинаем с default (если есть)
    import copy
    base = copy.deepcopy(config.get(DEFAULT_PROFILE, {}))
    
    # Мерджим с конкретным профилем
    if profile != DEFAULT_PROFILE and profile in config:
        profile_config = config[profile]
        base = _deep_merge(base, profile_config)
    
    # Мерджим с top-level ключами (не являющимися профилями)
    profile_keys = {DEFAULT_PROFILE, "production", "dev", "staging", "test"}
    for key, value in config.items():
        if key not in profile_keys:
            base[key] = value
    
    return base


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Глубокий merge двух словарей (override имеет приоритет).
    
    Для вложенных dict'ов делает рекурсивный merge.
    Для остальных типов — полная замена.
    """
    import copy
    result = copy.deepcopy(base)
    
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    
    return result


# =============================================================================
# INTERNAL: VALIDATION
# =============================================================================

def _validate_structure(config: Dict[str, Any], path: str) -> None:
    """
    Валидирует структуру конфига (обязательные секции, типы).
    
    Checks:
      - Наличие обязательных секций (paths).
      - Типы и содержимое критичных секций (paths).
      - Предупреждения о неизвестных ключах (возможные опечатки).
    """
    # 1. Required sections
    missing = REQUIRED_SECTIONS - config.keys()
    if missing:
        raise ConfigError(
            f"Missing required sections: {', '.join(sorted(missing))}",
            path=path
        )
    
    # 2. Optional sections (warning)
    missing_optional = OPTIONAL_SECTIONS - config.keys()
    if missing_optional:
        logger.info(
            f"Optional sections not present (using defaults): {', '.join(sorted(missing_optional))}"
        )
    
    # 3. Validate 'paths' section
    if "paths" in config:
        _validate_paths_section(config["paths"], path)


def _validate_paths_section(paths: Any, config_path: str) -> None:
    """Валидация секции 'paths'."""
    if not isinstance(paths, dict):
        raise ConfigError(
            "Section 'paths' must be a dictionary",
            path=config_path,
            key="paths"
        )
    
    # Required paths
    missing = REQUIRED_PATHS - paths.keys()
    if missing:
        raise ConfigError(
            f"Missing required paths: {', '.join(sorted(missing))}",
            path=config_path,
            key="paths"
        )
    
    # Unknown paths (warning о возможных опечатках)
    unknown = set(paths.keys()) - KNOWN_PATHS
    if unknown:
        logger.warning(
            f"Unknown paths in config (possible typo): {', '.join(sorted(unknown))}. "
            f"Known paths: {', '.join(sorted(KNOWN_PATHS))}"
        )
    
    # Type and emptiness checks
    for key, value in paths.items():
        if not isinstance(value, str):
            raise ConfigError(
                f"Path '{key}' must be a string, got {type(value).__name__}",
                path=config_path,
                key=f"paths.{key}"
            )
        
        if not value.strip():
            raise ConfigError(
                f"Path '{key}' cannot be empty",
                path=config_path,
                key=f"paths.{key}"
            )


# =============================================================================
# INTERNAL: IMMUTABILITY
# =============================================================================

def _deep_freeze(data: Any) -> Any:
    """
    Рекурсивно замораживает структуру данных.
    
    - dict → MappingProxyType (неизменяемый dict)
    - list → tuple (неизменяемый list)
    - Вложенные структуры обрабатываются рекурсивно
    
    Гарантирует, что конфиг не может быть изменён после загрузки.
    """
    if isinstance(data, dict):
        frozen_dict = {k: _deep_freeze(v) for k, v in data.items()}
        return MappingProxyType(frozen_dict)
    elif isinstance(data, list):
        return tuple(_deep_freeze(item) for item in data)
    else:
        return data


# =============================================================================
# CLI UTILITY (Optional — для отладки)
# =============================================================================

if __name__ == "__main__":
    """
    Утилита для проверки конфига из командной строки.
    
    Usage:
        python -m phantom.core.config
        python -m phantom.core.config --path /etc/phantom/phantom.yaml
        python -m phantom.core.config --validate
    """
    import argparse
    import json
    
    parser = argparse.ArgumentParser(description="Phantom Config Utility")
    parser.add_argument("--path", help="Path to config file")
    parser.add_argument("--profile", help="Profile to use (default/prod/dev)")
    parser.add_argument("--validate", action="store_true", help="Validate for daemon mode")
    parser.add_argument("--show", action="store_true", help="Print config as JSON")
    args = parser.parse_args()
    
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(levelname)s: %(message)s"
    )
    
    try:
        config = get_config(path=args.path, profile=args.profile)
        
        if args.validate:
            print("Running daemon validation checks...")
            validate_config_for_daemon()
            print("✓ Configuration is valid for daemon mode")
        
        if args.show:
            # Convert MappingProxyType to dict for JSON serialization
            def unfreeze(obj):
                if isinstance(obj, MappingProxyType):
                    return {k: unfreeze(v) for k, v in obj.items()}
                elif isinstance(obj, tuple):
                    return [unfreeze(item) for item in obj]
                return obj
            
            print(json.dumps(unfreeze(config), indent=2))
        
        if not args.validate and not args.show:
            print(f"✓ Configuration loaded successfully from {_get_default_config_path()}")
            print(f"  Profile: {get_profile()}")
            print(f"  Sections: {', '.join(sorted(config.keys()))}")
    
    except ConfigError as e:
        print(f"✗ Configuration error: {e}", file=sys.stderr)
        if e.path:
            print(f"  File: {e.path}", file=sys.stderr)
        if e.key:
            print(f"  Key: {e.key}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"✗ Unexpected error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(2)
