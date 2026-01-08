"""
manual_check.py
====================================
Скрипт для ручного тестирования и ВЕРИФИКАЦИИ генератора ловушек.
"""

import os
import sys
import time
import shutil
import logging
import zipfile

# --- Настройка путей импорта ---
current_dir = os.getcwd()
src_path = os.path.join(current_dir, 'src')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

try:
    from phantom.factory.manager import TrapFactory
except ImportError as e:
    sys.stderr.write(f"[CRITICAL] Import failed: {e}\n")
    sys.exit(1)

# 1. Настройка логирования
logging.basicConfig(
    level=logging.INFO, 
    format='[%(asctime)s] [%(levelname)s] %(message)s', 
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("TestRunner")

# 2. Мок-конфигурация
TRAPS_DIR = "./tests"
mock_config = {
    "paths": {
        "traps_dir": TRAPS_DIR,
        "templates": "./resources/templates",
        "manifest": "./config/traps_manifest.yaml"
    }
}

def clean_previous_run():
    if os.path.exists(TRAPS_DIR):
        shutil.rmtree(TRAPS_DIR)

def verify_files(startpath):
    """
    Проходит по всем созданным файлам и проверяет их качество:
    1. Time Stomping (дата должна быть старой).
    2. Integrity (бинарники не должны быть битыми).
    """
    print("\n--- INTEGRITY AND ATTRIBUTE VERIFICATION REPORT ---")
    print(f"{'STATUS':<10} {'OFFSET (DAYS)':<15} {'FILEPATH'}")
    print("-" * 80)
    
    issues = 0
    current_time = time.time()
    one_day_seconds = 86400

    for root, dirs, files in os.walk(startpath):
        level = root.replace(startpath, '').count(os.sep)
        indent = ' ' * 4 * (level)
        print(f"{indent}[DIR] {os.path.basename(root)}/")
        
        subindent = ' ' * 4 * (level + 1)
        for f in files:
            filepath = os.path.join(root, f)
            try:
                stats = os.stat(filepath)
            except OSError:
                print(f"{subindent}[ERR] {f} (Access Denied)")
                issues += 1
                continue
            
            # Проверка 1: Time Stomping
            # Файл должен быть старше 24 часов (мы генерируем от 10 дней назад)
            age_seconds = current_time - stats.st_mtime
            is_old = age_seconds > one_day_seconds
            
            # Проверка 2: Бинарная целостность (для Office)
            is_valid_zip = True
            if f.endswith(('.docx', '.xlsx')):
                if not zipfile.is_zipfile(filepath):
                    is_valid_zip = False
                else:
                    try:
                        with zipfile.ZipFile(filepath) as zf:
                            if zf.testzip() is not None:
                                is_valid_zip = False
                    except:
                        is_valid_zip = False

            # Вывод статуса
            status_tag = "[OK]"
            details = []
            
            if not is_old:
                status_tag = "[WARN]"
                details.append("FRESH_TIME (0d)")
                issues += 1
            else:
                file_date = time.strftime('%Y-%m-%d', time.localtime(stats.st_mtime))
                details.append(f"TS_Date:{file_date}")

            if not is_valid_zip:
                status_tag = "[FAIL]"
                details.append("CORRUPTED_STRUCTURE")
                issues += 1

            details_str = " | ".join(details)
            print(f"{subindent}{status_tag:<8} {f:<30} {details_str}")

    return issues

def main():
    logger.info("Initiating deployment and audit sequence...")
    clean_previous_run()

    try:
        # Инициализация и Генерация
        factory = TrapFactory(mock_config)
        summary = factory.deploy_traps()

        deployed = summary.get('deployed', 0)
        
        if deployed == 0:
            logger.error("Operation aborted: No artifacts generated.")
            return

        # Запуск верификации
        issues = verify_files(TRAPS_DIR)
        
        print("\n" + "="*40)
        if issues == 0:
            logger.info("AUDIT PASSED: All artifacts meet compliance standards.")
        else:
            logger.warning(f"AUDIT COMPLETED WITH FINDINGS: {issues} non-compliant artifacts detected.")

    except Exception as e:
        logger.critical(f"System exception: {e}", exc_info=True)

if __name__ == "__main__":
    main()
