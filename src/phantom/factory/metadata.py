import os
import random
import time
import logging
from typing import Optional, Dict, Any

# Инициализация логгера для модуля метаданных
logger = logging.getLogger("Factory.Meta")

# Значения по умолчанию для Time Stomping
DEFAULT_MIN_DAYS = 10
DEFAULT_MAX_DAYS = 300
DEFAULT_ATIME_OFFSET_MIN = 5
DEFAULT_ATIME_OFFSET_MAX = 300


def stomp_timestamp(
    filepath: str,
    config: Optional[Dict[str, Any]] = None
) -> None:
    """
    Применяет технику Anti-Forensics: Time Stomping (подделка временных меток).

    Изменяет время последнего доступа (atime) и модификации (mtime) файла,
    сдвигая их в прошлое. Это создает иллюзию, что файл является "старым"
    и легитимным артефактом системы, а не свежесозданной ловушкой.

    Args:
        filepath (str): Полный или относительный путь к целевому файлу.
        config (Optional[Dict[str, Any]]): Словарь конфигурации с параметрами:
            - min_days_ago (int): Минимальный "возраст" файла в днях.
            - max_days_ago (int): Максимальный "возраст" файла в днях.
            - atime_offset_min (int): Мин. смещение atime от mtime (сек).
            - atime_offset_max (int): Макс. смещение atime от mtime (сек).
    """
    
    # Защита: если файла нет, просто выходим, не ломая программу
    if not os.path.exists(filepath):
        logger.debug(f"File not found for stomping: {filepath}")
        return

    # Извлекаем параметры из конфига или используем значения по умолчанию
    cfg = config or {}
    min_days = cfg.get("min_days_ago", DEFAULT_MIN_DAYS)
    max_days = cfg.get("max_days_ago", DEFAULT_MAX_DAYS)
    atime_min = cfg.get("atime_offset_min", DEFAULT_ATIME_OFFSET_MIN)
    atime_max = cfg.get("atime_offset_max", DEFAULT_ATIME_OFFSET_MAX)

    try:
        # 1. Определяем "возраст" файла
        days_ago = random.randint(min_days, max_days)
        
        # 2. Добавляем "шум" (секунды внутри суток), чтобы время не было ровно 00:00:00
        seconds_in_day = 86400
        noise = random.randint(0, seconds_in_day)
        
        # 3. Вычисляем целевое время модификации (когда файл был "написан")
        current_time = time.time()
        mtime = current_time - (days_ago * seconds_in_day) - noise
        
        # 4. Вычисляем время доступа (когда файл был "прочитан")
        # Логика: файл создали, а через N секунд проверили (cat/open).
        # atime должен быть >= mtime.
        atime = mtime + random.randint(atime_min, atime_max)

        # 5. Применяем изменения к inode файла
        os.utime(filepath, (atime, mtime))
        
        logger.debug(f"Time stomped: {os.path.basename(filepath)} -> {days_ago} days ago")
        
    except OSError as e:
        # Ловим системные ошибки (например, нет прав доступа), но не прерываем работу демона
        logger.warning(f"Failed to stomp time for {filepath}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error in metadata module: {e}")

