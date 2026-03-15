# Используем супер-легкий Alpine Linux (весит 5 МБ)
FROM alpine:latest

# Устанавливаем инструменты для форензики (анализа)
# tcpdump - для перехвата трафика
# strace - для отслеживания системных вызовов (если нужно)
# net-tools - для netstat
# bash - для удобства
RUN apk add --no-cache tcpdump strace net-tools bash coreutils

# Создаем папку для улик
WORKDIR /evidence

# По умолчанию запускаем tcpdump, чтобы слушать трафик
# (Это можно переопределить в Python-коде)
CMD ["/bin/sh"]