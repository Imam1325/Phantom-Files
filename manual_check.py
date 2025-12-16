import os
import shutil
import logging
from src.phantom.factory.manager import TrapFactory

# 1. Настройка логирования, чтобы видеть процесс в консоли
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# 2. Фейковый конфиг (чтобы не парсить yaml-файлы конфигурации, зададим пути напрямую)
# Мы говорим генератору класть ловушки в папку 'test_output', чтобы не мусорить в /tmp
mock_config = {
    "paths": {
        "traps_dir": "./test_output_traps",
        "templates": "./resources/templates",
        "manifest": "./config/traps_manifest.yaml"
    },
    "factory": {
        "locale": "en_US" # Или "ru_RU"
    }
}

def clean_previous_run():
    """Удаляет папку с прошлым тестом, если есть"""
    if os.path.exists(mock_config["paths"]["traps_dir"]):
        shutil.rmtree(mock_config["paths"]["traps_dir"])
        print("🧹 Cleaned up previous test output.")

def main():
    print("🚀 Starting Manual Generator Check...")
    
    # Очистка
    clean_previous_run()

    try:
        # Инициализация Фабрики
        factory = TrapFactory(mock_config)
        
        # Запуск генерации
        summary = factory.deploy_traps()
        
        print("\n" + "="*30)
        print(f"📊 REPORT:")
        print(f"Deployed: {summary['deployed']}")
        print(f"Total tasks: {summary['total']}")
        print("="*30 + "\n")
        
        if summary['deployed'] > 0:
            print(f"✅ SUCCESS! Check the folder: {mock_config['paths']['traps_dir']}")
        else:
            print("❌ FAILURE! No traps generated. Check logs above.")

    except Exception as e:
        print(f"🔥 CRITICAL ERROR: {e}")

if __name__ == "__main__":
    main()