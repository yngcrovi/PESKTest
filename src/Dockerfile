FROM python:3.10.12-slim

WORKDIR /app

# Копирование зависимостей
COPY requirements.txt .

# Установка зависимостей
RUN pip install --no-cache-dir -r requirements.txt

# Копирование кода
COPY . .

EXPOSE 8000

# Запуск приложения
CMD ["python3", "main.py"]