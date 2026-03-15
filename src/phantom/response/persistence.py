"""
Сканер механизмов закрепления (persistence) на хосте.

После обнаружения инцидента сканирует хост на следы закрепления атакующего:
- cron задачи (crontab, /etc/cron.*, systemd timers)
- SSH authorized_keys (новые/изменённые ключи)
- Systemd unit-файлы (подозрительные сервисы)
- Shell RC-файлы (.bashrc, .profile, .zshrc)
- At jobs
- Модифицированные бинарники в PATH
- Активные сессии пользователя (pts/tty, SSH)

В active режиме может нейтрализовать найденные механизмы.
"""

from __future__ import annotations

import asyncio
import logging
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("phantom.persistence")

# Подозрительные паттерны в cron/shell файлах
_SUSPICIOUS_PATTERNS = re.compile(
    r"(bash\s+-i\s+>&|/dev/tcp/|nc\s+-[elp]|ncat\s|mkfifo|"
    r"curl\s.*\|\s*(ba)?sh|wget\s.*\|\s*(ba)?sh|"
    r"python\s+-c\s.*socket|perl\s+-e\s.*socket|"
    r"socat\s|/tmp/\.[\w]+|chmod\s+[u+]*s\s|"
    r"base64\s+-d\s*\|\s*(ba)?sh)",
    re.IGNORECASE,
)

# Директории cron
_CRON_DIRS = [
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron/crontabs",
    "/var/spool/cron",
]

# Shell RC-файлы (проверяем для конкретного пользователя)
_SHELL_RC_FILES = [
    ".bashrc", ".bash_profile", ".bash_login", ".profile",
    ".zshrc", ".zprofile", ".zlogin",
    ".config/fish/config.fish",
]


@dataclass
class PersistenceFinding:
    """Одна найденная точка закрепления."""
    category: str       # cron, ssh_key, systemd, shell_rc, at_job, binary, session
    severity: str       # critical, high, medium, low
    path: str           # путь к файлу или описание
    detail: str         # подробности (содержимое строки, имя сервиса, etc.)
    user: str           # владелец / связанный пользователь
    neutralized: bool = False   # было ли нейтрализовано
    neutralize_detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "severity": self.severity,
            "path": self.path,
            "detail": self.detail,
            "user": self.user,
            "neutralized": self.neutralized,
            "neutralize_detail": self.neutralize_detail,
        }


@dataclass
class PersistenceScanResult:
    """Результат сканирования на persistence."""
    findings: list[PersistenceFinding] = field(default_factory=list)
    scanned_at: str = ""
    target_uid: int | None = None
    target_user: str = ""
    sessions_killed: int = 0
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "scanned_at": self.scanned_at,
            "target_uid": self.target_uid,
            "target_user": self.target_user,
            "sessions_killed": self.sessions_killed,
            "scan_duration_seconds": self.scan_duration_seconds,
        }


class PersistenceScanner:
    """
    Сканер механизмов закрепления.

    Использование:
        scanner = PersistenceScanner()
        result = await scanner.scan(pid=12345, neutralize=True)
    """

    async def scan(
        self,
        pid: int,
        neutralize: bool = False,
        timeout: float = 30.0,
    ) -> PersistenceScanResult:
        """
        Сканирование хоста на persistence-механизмы, связанные с процессом.

        Args:
            pid: PID подозрительного процесса.
            neutralize: Если True — нейтрализовать найденные механизмы.
            timeout: Максимальное время сканирования.
        """
        import time as _time
        start = _time.monotonic()
        result = PersistenceScanResult(
            scanned_at=datetime.now(timezone.utc).isoformat(),
        )

        # Определяем UID и username атакующего по PID
        uid, username = await asyncio.to_thread(self._resolve_user, pid)
        result.target_uid = uid
        result.target_user = username or f"uid:{uid}" if uid is not None else "unknown"

        if uid is None:
            logger.warning("Cannot resolve UID for PID %s, limited scan", pid)
            result.scan_duration_seconds = round(_time.monotonic() - start, 2)
            return result

        deadline = start + timeout

        # Параллельное сканирование всех категорий
        scan_tasks = [
            asyncio.to_thread(self._scan_cron, uid, username, deadline),
            asyncio.to_thread(self._scan_ssh_keys, uid, username, deadline),
            asyncio.to_thread(self._scan_systemd_units, uid, username, deadline),
            asyncio.to_thread(self._scan_shell_rc, uid, username, deadline),
            asyncio.to_thread(self._scan_at_jobs, uid, username, deadline),
            asyncio.to_thread(self._scan_active_sessions, uid, username, deadline),
        ]
        scan_results = await asyncio.gather(*scan_tasks, return_exceptions=True)

        for scan_result in scan_results:
            if isinstance(scan_result, list):
                result.findings.extend(scan_result)
            elif isinstance(scan_result, BaseException):
                logger.warning("Persistence scan task failed: %s", scan_result)

        # Нейтрализация если запрошена
        if neutralize and result.findings:
            n_killed = await asyncio.to_thread(
                self._neutralize, result.findings, uid, username
            )
            result.sessions_killed = n_killed

        result.scan_duration_seconds = round(_time.monotonic() - start, 2)
        logger.info(
            "Persistence scan complete: user=%s findings=%d neutralized=%d duration=%.1fs",
            result.target_user,
            len(result.findings),
            sum(1 for f in result.findings if f.neutralized),
            result.scan_duration_seconds,
        )
        return result

    async def kill_user_sessions(self, pid: int) -> int:
        """Убить все сессии пользователя, которому принадлежит PID."""
        uid, username = await asyncio.to_thread(self._resolve_user, pid)
        if username is None:
            return 0
        return await asyncio.to_thread(self._kill_sessions, username)

    # ---------- Резолв пользователя ----------

    def _resolve_user(self, pid: int) -> tuple[int | None, str | None]:
        """Определение UID и username по PID."""
        status_path = Path(f"/proc/{pid}/status")
        if not status_path.exists():
            return None, None
        try:
            text = status_path.read_text(encoding="utf-8", errors="ignore")
            for line in text.splitlines():
                if line.startswith("Uid:"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        uid = int(parts[1])
                        import pwd
                        try:
                            username = pwd.getpwuid(uid).pw_name
                        except KeyError:
                            username = None
                        return uid, username
        except Exception:
            pass
        return None, None

    # ---------- Сканеры по категориям ----------

    def _scan_cron(self, uid: int, username: str | None, deadline: float) -> list[PersistenceFinding]:
        """Сканирование cron задач."""
        import time as _time
        findings: list[PersistenceFinding] = []

        # Пользовательский crontab
        if username:
            try:
                proc = subprocess.run(
                    ["crontab", "-l", "-u", username],
                    check=False, capture_output=True, text=True, timeout=5,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    for line in proc.stdout.strip().splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        severity = "high" if _SUSPICIOUS_PATTERNS.search(line) else "medium"
                        findings.append(PersistenceFinding(
                            category="cron",
                            severity=severity,
                            path=f"crontab -u {username}",
                            detail=line[:500],
                            user=username or str(uid),
                        ))
            except Exception:
                pass

        # Системные cron-директории
        for cron_dir in _CRON_DIRS:
            if _time.monotonic() >= deadline:
                break
            p = Path(cron_dir)
            if not p.exists():
                continue
            for cron_file in p.iterdir():
                if not cron_file.is_file():
                    continue
                try:
                    stat = cron_file.stat()
                    # Проверяем файлы, принадлежащие атакующему UID
                    if stat.st_uid == uid:
                        text = cron_file.read_text(encoding="utf-8", errors="ignore")[:4096]
                        severity = "critical" if _SUSPICIOUS_PATTERNS.search(text) else "high"
                        findings.append(PersistenceFinding(
                            category="cron",
                            severity=severity,
                            path=str(cron_file),
                            detail=text[:500],
                            user=username or str(uid),
                        ))
                except Exception:
                    continue

        return findings

    def _scan_ssh_keys(self, uid: int, username: str | None, deadline: float) -> list[PersistenceFinding]:
        """Сканирование SSH authorized_keys на добавленные ключи."""
        findings: list[PersistenceFinding] = []
        if not username:
            return findings

        # Определяем home-директорию
        import pwd
        try:
            home = Path(pwd.getpwuid(uid).pw_dir)
        except KeyError:
            return findings

        auth_keys = home / ".ssh" / "authorized_keys"
        if not auth_keys.exists():
            return findings

        try:
            stat = auth_keys.stat()
            text = auth_keys.read_text(encoding="utf-8", errors="ignore")
            keys = [
                line.strip()
                for line in text.splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]

            if keys:
                # Каждый ключ — потенциальная точка возврата
                for key_line in keys:
                    # Извлекаем комментарий (обычно email или hostname)
                    parts = key_line.split()
                    comment = parts[-1] if len(parts) >= 3 else "unknown"
                    findings.append(PersistenceFinding(
                        category="ssh_key",
                        severity="high",
                        path=str(auth_keys),
                        detail=f"SSH key: {comment} (key_type={parts[0] if parts else 'unknown'})",
                        user=username,
                    ))

            # Проверяем права — должно быть 600
            mode = oct(stat.st_mode & 0o777)
            if mode != "0o600":
                findings.append(PersistenceFinding(
                    category="ssh_key",
                    severity="medium",
                    path=str(auth_keys),
                    detail=f"Insecure permissions: {mode} (expected 0o600)",
                    user=username,
                ))
        except Exception:
            pass

        return findings

    def _scan_systemd_units(self, uid: int, username: str | None, deadline: float) -> list[PersistenceFinding]:
        """Сканирование systemd unit-файлов."""
        import time as _time
        findings: list[PersistenceFinding] = []

        # Пользовательские systemd сервисы
        if username:
            import pwd
            try:
                home = Path(pwd.getpwuid(uid).pw_dir)
            except KeyError:
                home = None

            if home:
                user_systemd = home / ".config" / "systemd" / "user"
                if user_systemd.exists():
                    for unit_file in user_systemd.rglob("*.service"):
                        if _time.monotonic() >= deadline:
                            break
                        try:
                            text = unit_file.read_text(encoding="utf-8", errors="ignore")[:4096]
                            severity = "critical" if _SUSPICIOUS_PATTERNS.search(text) else "high"
                            findings.append(PersistenceFinding(
                                category="systemd",
                                severity=severity,
                                path=str(unit_file),
                                detail=text[:500],
                                user=username,
                            ))
                        except Exception:
                            continue

        # Системные unit-файлы, принадлежащие UID (обычно только root создаёт, но проверим)
        for unit_dir in ["/etc/systemd/system", "/run/systemd/system"]:
            if _time.monotonic() >= deadline:
                break
            p = Path(unit_dir)
            if not p.exists():
                continue
            for unit_file in p.glob("*.service"):
                try:
                    if unit_file.stat().st_uid == uid and uid != 0:
                        text = unit_file.read_text(encoding="utf-8", errors="ignore")[:4096]
                        findings.append(PersistenceFinding(
                            category="systemd",
                            severity="critical",
                            path=str(unit_file),
                            detail=text[:500],
                            user=username or str(uid),
                        ))
                except Exception:
                    continue

        return findings

    def _scan_shell_rc(self, uid: int, username: str | None, deadline: float) -> list[PersistenceFinding]:
        """Сканирование shell RC-файлов на подозрительные вставки."""
        findings: list[PersistenceFinding] = []
        if not username:
            return findings

        import pwd
        try:
            home = Path(pwd.getpwuid(uid).pw_dir)
        except KeyError:
            return findings

        for rc_name in _SHELL_RC_FILES:
            rc_path = home / rc_name
            if not rc_path.exists():
                continue
            try:
                text = rc_path.read_text(encoding="utf-8", errors="ignore")
                if _SUSPICIOUS_PATTERNS.search(text):
                    # Найти конкретные подозрительные строки
                    for i, line in enumerate(text.splitlines(), 1):
                        if _SUSPICIOUS_PATTERNS.search(line):
                            findings.append(PersistenceFinding(
                                category="shell_rc",
                                severity="critical",
                                path=f"{rc_path}:{i}",
                                detail=line.strip()[:500],
                                user=username,
                            ))
            except Exception:
                continue

        return findings

    def _scan_at_jobs(self, uid: int, username: str | None, deadline: float) -> list[PersistenceFinding]:
        """Сканирование at-jobs."""
        findings: list[PersistenceFinding] = []
        if not username:
            return findings

        try:
            proc = subprocess.run(
                ["atq"],
                check=False, capture_output=True, text=True, timeout=5,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                for line in proc.stdout.strip().splitlines():
                    # atq формат: "1\t2026-03-13 10:00 a user"
                    if username in line:
                        findings.append(PersistenceFinding(
                            category="at_job",
                            severity="high",
                            path="atq",
                            detail=line.strip()[:500],
                            user=username,
                        ))
        except Exception:
            pass

        return findings

    def _scan_active_sessions(self, uid: int, username: str | None, deadline: float) -> list[PersistenceFinding]:
        """Сканирование активных сессий пользователя."""
        findings: list[PersistenceFinding] = []
        if not username:
            return findings

        try:
            # who показывает активные сессии
            proc = subprocess.run(
                ["who"],
                check=False, capture_output=True, text=True, timeout=5,
            )
            if proc.returncode == 0:
                for line in proc.stdout.strip().splitlines():
                    if line.startswith(username + " ") or line.startswith(username + "\t"):
                        findings.append(PersistenceFinding(
                            category="session",
                            severity="high",
                            path="active_session",
                            detail=line.strip()[:500],
                            user=username,
                        ))
        except Exception:
            pass

        # Проверяем /proc на процессы этого UID
        try:
            count = 0
            for pid_dir in Path("/proc").iterdir():
                if not pid_dir.name.isdigit():
                    continue
                try:
                    status = (pid_dir / "status").read_text(encoding="utf-8", errors="ignore")
                    for sline in status.splitlines():
                        if sline.startswith("Uid:"):
                            parts = sline.split()
                            if len(parts) >= 2 and parts[1] == str(uid):
                                count += 1
                            break
                except Exception:
                    continue
            if count > 0:
                findings.append(PersistenceFinding(
                    category="session",
                    severity="medium",
                    path="/proc",
                    detail=f"Active processes owned by UID {uid}: {count}",
                    user=username,
                ))
        except Exception:
            pass

        return findings

    # ---------- Нейтрализация ----------

    def _neutralize(
        self, findings: list[PersistenceFinding], uid: int, username: str | None,
    ) -> int:
        """
        Нейтрализация найденных механизмов закрепления.

        Принцип: не удаляем файлы, а делаем их безвредными
        (переименование с суффиксом .phantom_disabled, удаление cron).
        """
        sessions_killed = 0

        for finding in findings:
            try:
                if finding.category == "cron" and finding.path.startswith("crontab"):
                    # Удаляем пользовательский crontab
                    if username:
                        proc = subprocess.run(
                            ["crontab", "-r", "-u", username],
                            check=False, capture_output=True, text=True, timeout=5,
                        )
                        if proc.returncode == 0:
                            finding.neutralized = True
                            finding.neutralize_detail = "User crontab removed"
                            logger.info("Neutralized: removed crontab for %s", username)

                elif finding.category == "cron" and Path(finding.path).is_file():
                    # Переименовываем cron-файл
                    src = Path(finding.path)
                    dst = src.with_suffix(src.suffix + ".phantom_disabled")
                    src.rename(dst)
                    finding.neutralized = True
                    finding.neutralize_detail = f"Renamed to {dst.name}"
                    logger.info("Neutralized: renamed %s -> %s", src, dst)

                elif finding.category == "shell_rc":
                    # Для shell RC: добавляем комментарий-блокировку
                    # Не удаляем файл целиком — может сломать систему
                    path_str = finding.path.split(":")[0]  # убираем номер строки
                    rc_path = Path(path_str)
                    if rc_path.is_file():
                        text = rc_path.read_text(encoding="utf-8", errors="ignore")
                        new_text = _SUSPICIOUS_PATTERNS.sub(
                            r"# [PHANTOM DISABLED] \g<0>", text
                        )
                        if new_text != text:
                            rc_path.write_text(new_text, encoding="utf-8")
                            finding.neutralized = True
                            finding.neutralize_detail = "Suspicious lines commented out"
                            logger.info("Neutralized: commented suspicious lines in %s", rc_path)

                elif finding.category == "systemd" and Path(finding.path).is_file():
                    # Останавливаем и отключаем сервис
                    unit_name = Path(finding.path).name
                    subprocess.run(
                        ["systemctl", "stop", unit_name],
                        check=False, capture_output=True, timeout=5,
                    )
                    subprocess.run(
                        ["systemctl", "disable", unit_name],
                        check=False, capture_output=True, timeout=5,
                    )
                    src = Path(finding.path)
                    dst = src.with_suffix(src.suffix + ".phantom_disabled")
                    src.rename(dst)
                    finding.neutralized = True
                    finding.neutralize_detail = f"Service stopped, disabled, renamed to {dst.name}"
                    logger.info("Neutralized: disabled systemd unit %s", unit_name)

                elif finding.category == "at_job":
                    # Удаляем at-job
                    parts = finding.detail.split()
                    if parts and parts[0].isdigit():
                        job_id = parts[0]
                        proc = subprocess.run(
                            ["atrm", job_id],
                            check=False, capture_output=True, text=True, timeout=5,
                        )
                        if proc.returncode == 0:
                            finding.neutralized = True
                            finding.neutralize_detail = f"At job {job_id} removed"
                            logger.info("Neutralized: removed at job %s", job_id)

                elif finding.category == "session" and finding.path == "active_session":
                    # Убиваем сессии пользователя
                    if username:
                        n = self._kill_sessions(username)
                        sessions_killed += n
                        if n > 0:
                            finding.neutralized = True
                            finding.neutralize_detail = f"Killed {n} sessions"

            except Exception as exc:
                logger.warning("Neutralization failed for %s: %s", finding.path, exc)

        return sessions_killed

    def _kill_sessions(self, username: str) -> int:
        """Убить все сессии пользователя через pkill."""
        if not username or username == "root":
            logger.warning("Refused to kill sessions for user=%s", username)
            return 0
        try:
            # pkill -u username убивает все процессы пользователя
            # Используем SIGTERM сначала
            subprocess.run(
                ["pkill", "-TERM", "-u", username],
                check=False, capture_output=True, timeout=5,
            )
            # Даём время на graceful shutdown
            import time as _time
            _time.sleep(1)
            # SIGKILL для оставшихся
            subprocess.run(
                ["pkill", "-KILL", "-u", username],
                check=False, capture_output=True, timeout=5,
            )
            logger.info("Killed all sessions for user %s", username)
            return 1  # Как минимум одна попытка
        except Exception as exc:
            logger.error("Failed to kill sessions for %s: %s", username, exc)
            return 0
