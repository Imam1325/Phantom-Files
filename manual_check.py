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
    print(f"❌ Import Error: {e}")
    sys.exit(1)

# 1. Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(message)s') # Упростили формат для красоты
logger = logging.getLogger("ManualCheck")

# 2. Мок-конфигурация
TRAPS_DIR = "./test_output_traps"
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
    print("\n🔍 VERIFICATION REPORT:")
    print(f"Root: {startpath}")
    
    issues = 0
    current_time = time.time()
    one_day_seconds = 86400

    for root, dirs, files in os.walk(startpath):
        level = root.replace(startpath, '').count(os.sep)
        indent = ' ' * 4 * (level)
        print(f"{indent}📂 {os.path.basename(root)}/")
        
        subindent = ' ' * 4 * (level + 1)
        for f in files:
            filepath = os.path.join(root, f)
            stats = os.stat(filepath)
            
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
            status_icon = "✅"
            details = []
            
            if not is_old:
                status_icon = "⚠️"
                details.append("FRESH TIME")
                issues += 1
            else:
                # Показываем дату для подтверждения
                file_date = time.strftime('%Y-%m-%d', time.localtime(stats.st_mtime))
                details.append(f"Date: {file_date}")

            if not is_valid_zip:
                status_icon = "❌"
                details.append("CORRUPTED ZIP")
                issues += 1

            print(f"{subindent}{status_icon} {f}  [{', '.join(details)}]")

    return issues

def main():
    print("🚀 Starting Manual Generator Check...")
    clean_previous_run()

    try:
        # Инициализация и Генерация
        factory = TrapFactory(mock_config)
        summary = factory.deploy_traps()
        
        # Отчет о генерации
        print("\n" + "="*40)
        print(f"📊 GENERATION SUMMARY:")
        print(f"Deployed:    {summary.get('deployed', 0)}")
        print(f"Total tasks: {summary.get('total', 0)}")
        print("="*40)
        
        if summary.get('deployed', 0) == 0:
            print("❌ FAILURE! No traps generated.")
            return

        # Запуск верификации
        issues = verify_files(TRAPS_DIR)
        
        print("\n" + "="*40)
        if issues == 0:
            print("🎉 ALL TESTS PASSED! Traps are valid and look old.")
        else:
            print(f"⚠️ FOUND {issues} ISSUES (See details above).")

    except Exception as e:
        print(f"🔥 CRITICAL ERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()