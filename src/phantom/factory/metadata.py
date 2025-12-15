import os, random, time, logging

logger = logging.getLogger("Factory.Meta")

def stomp_timestamp(filepath: str):
    """
    Применяет технику Time Stomping: меняет время создания (ctime) 
    и модификации (mtime) файла на случайное в прошлом.
    """
    if not os.path.exists(filepath):
        return

    try:
        # Генерируем случайное время: от 10 до 300 дней назад
        days_ago = random.randint(10, 300)
        # Добавляем шум (секунды), чтобы время не было ровно 00:00:00
        noise = random.randint(0, 86400)
        
        mtime = time.time() - (days_ago * 86400) - noise
        atime = mtime + random.randint(5, 300)

        # Меняем и atime, и mtime файла
        os.utime(filepath, (atime, mtime))
        
        logger.debug(f"⏳ Time stomped: {os.path.basename(filepath)} -> {days_ago} days ago")
        
    except Exception as e:
        logger.warning(f"Failed to stomp time for {filepath}: {e}")