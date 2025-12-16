# Объявляем "виртуальные" цели, чтобы Make не искал файлы с такими именами
.PHONY: install build-image run check clean help

# --- 1. УСТАНОВКА ---
# Устанавливает проект в режиме разработки и собирает Docker-образ
install:
	@echo "📦 Installing Python dependencies..."
	pip install -e .
	@echo "🐳 Building Forensic Sandbox Image..."
	$(MAKE) build-image
	@echo "✅ Installation complete!"

# Сборка специального образа для песочницы (с tcpdump и strace)
build-image:
	docker build -t phantom-forensics:v1 -f resources/docker/Dockerfile .

# --- 2. ЗАПУСК ---
# Запуск основного демона (требует прав root для системных путей, но для теста можно и так)
run:
	@echo "👻 Starting Phantom Daemon..."
	python3 -m phantom.main

# Запуск ручной проверки генератора (твой скрипт)
check:
	@echo "🧪 Running Manual Generator Check..."
	python3 manual_check.py

# --- 3. ОЧИСТКА ---
# Удаляет весь мусор: кэши, билды, тестовые ловушки
clean:
	@echo "🧹 Cleaning up..."
	rm -rf build dist *.egg-info
	find . -name "__pycache__" -type d -exec rm -rf {} +
	find . -name "*.pyc" -delete
	rm -rf test_output_traps
	rm -rf /tmp/phantom_traps
	rm -rf /tmp/phantom_logs
	@echo "✨ Cleaned!"

# --- 4. ПОМОЩЬ ---
help:
	@echo "Phantom Files Makefile"
	@echo "----------------------"
	@echo "make install      - Установить зависимости и собрать Docker-образ"
	@echo "make run          - Запустить демона (phantomd)"
	@echo "make check        - Запустить тест генератора (manual_check.py)"
	@echo "make clean        - Удалить мусор и временные файлы"