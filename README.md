# Phishing Scanner

Эвристическая проверка email-писем на признаки фишинга. Вставьте текст письма
(в идеале — с заголовками) или загрузите `.eml`/`.txt`, получите риск-скор
0–100 и разбор находок. Вся логика работает локально, без внешних API и без
сохранения данных.

Подробности — в [prd.md](prd.md).

## Структура

- `phishing_analyzer.py` — движок анализа (единственный источник логики).
- `bot.py` — Telegram-бот.
- `app.py` — веб-приложение (Flask).
- `templates/`, `static/` — фронтенд веб-версии.
- `tests/` — тесты движка.

## Установка

```
pip install -r requirements.txt
```

## Веб-приложение

```
python app.py
```

Откройте http://localhost:5000. Порт настраивается переменной `PORT`.

## Telegram-бот

```
set TELEGRAM_BOT_TOKEN=ваш_токен_от_botfather
python bot.py
```

(На Linux/macOS — `export TELEGRAM_BOT_TOKEN=...`.) Токен никогда не
хардкодится в коде — см. `.env.example`.

## Тесты

```
python -m unittest discover tests
```
