import os
import random
import time
import logging

# Инициализация логгера для модуля метаданных
logger = logging.getLogger("Factory.Meta")

def stomp_timestamp(filepath: str) -> None:
    """
    Применяет технику Anti-Forensics: Time Stomping (подделка временных меток).

    Изменяет время последнего доступа (atime) и модификации (mtime) файла,
    сдвигая их в прошлое. Это создает иллюзию, что файл является "старым"
    и легитимным артефактом системы, а не свежесозданной ловушкой.

    Args:
        filepath (str): Полный или относительный путь к целевому файлу.
    """
    
    # Защита: если файла нет, просто выходим, не ломая программу
    if not os.path.exists(filepath):
        logger.debug(f"File not found for stomping: {filepath}")
        return

    try:
        # 1. Определяем "возраст" файла (от 10 до 300 дней назад)
        days_ago = random.randint(10, 300)
        
        # 2. Добавляем "шум" (секунды внутри суток), чтобы время не было ровно 00:00:00
        seconds_in_day = 86400
        noise = random.randint(0, seconds_in_day)
        
        # 3. Вычисляем целевое время модификации (когда файл был "написан")
        current_time = time.time()
        mtime = current_time - (days_ago * seconds_in_day) - noise
        
        # 4. Вычисляем время доступа (когда файл был "прочитан")
        # Логика: файл создали, а через 5-300 секунд проверили (cat/open).
        # atime должен быть >= mtime.
        atime = mtime + random.randint(5, 300)

        # 5. Применяем изменения к inode файла
        os.utime(filepath, (atime, mtime))
        
        logger.debug(f"Time stomped: {os.path.basename(filepath)} -> {days_ago} days ago")
        
    except OSError as e:
        # Ловим системные ошибки (например, нет прав доступа), но не прерываем работу демона
        logger.warning(f"Failed to stomp time for {filepath}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error in metadata module: {e}")
