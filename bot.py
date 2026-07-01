"""Telegram bot frontend for Phishing Scanner.

Thin wrapper around phishing_analyzer.analyze_email(). No detection logic
lives here. Bot token is read from the TELEGRAM_BOT_TOKEN env var — never
hardcoded (FR-14).
"""

import logging
import os

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from phishing_analyzer import analyze_email

logging.basicConfig(
    format="%(asctime)s %(name)s %(levelname)s %(message)s", level=logging.INFO
)
logger = logging.getLogger("phishing-scanner-bot")

MAX_TEXT_LEN = 20000
SEVERITY_ICONS = {"high": "🔴", "medium": "🟠", "low": "🟡"}
ALLOWED_DOCUMENT_EXT = (".eml", ".txt")

WELCOME = (
    "👋 Я *Phishing Scanner*.\n\n"
    "Пришлите мне текст письма (лучше с заголовками From/To/Subject) или "
    "прикрепите `.eml`/`.txt` файл — я проверю его на признаки фишинга и "
    "верну риск-скор с разбором находок.\n\n"
    "Команды:\n"
    "/start — это сообщение\n"
    "/help — как пользоваться ботом"
)

HELP = (
    "*Как пользоваться:*\n\n"
    "1️⃣ Скопируйте письмо целиком (по возможности вместе с заголовками — "
    "From, Reply-To, Authentication-Results) и отправьте сообщением.\n"
    "2️⃣ Либо прикрепите `.eml` или `.txt` файл.\n\n"
    "Я не перехожу по ссылкам и не сохраняю текст письма — анализ полностью "
    "локальный."
)


def _format_result(result: dict) -> str:
    lines = [
        f"{result['verdict_emoji']} *{result['verdict_label']}* — риск-скор `{result['score']}/100`",
    ]
    if not result["is_raw_email"]:
        lines.append("_Заголовки писем не обнаружены — анализ выполнен по тексту и ссылкам._")

    flags = result["flags"]
    if flags:
        lines.append("\n*Находки:*")
        for f in flags:
            icon = SEVERITY_ICONS.get(f["severity"], "⚪")
            lines.append(f"{icon} {f['message']}")
    else:
        lines.append("\nПодозрительных признаков не найдено.")

    links = result["links"]
    if links:
        lines.append(f"\n*Ссылки (показано {min(10, len(links))} из {result['total_links']}):*")
        for link in links[:10]:
            marker = "⚠️" if link["flags"] else "•"
            lines.append(f"{marker} `{link['url']}`")

    return "\n".join(lines)


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(WELCOME, parse_mode=ParseMode.MARKDOWN)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(HELP, parse_mode=ParseMode.MARKDOWN)


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (update.message.text or "")[:MAX_TEXT_LEN]
    if not text.strip():
        await update.message.reply_text("Пустое сообщение — нечего анализировать.")
        return
    result = analyze_email(text)
    await update.message.reply_text(_format_result(result), parse_mode=ParseMode.MARKDOWN)


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    document = update.message.document
    filename = (document.file_name or "").lower()
    if not filename.endswith(ALLOWED_DOCUMENT_EXT):
        await update.message.reply_text("Поддерживаются только файлы .eml и .txt.")
        return

    file = await document.get_file()
    raw_bytes = await file.download_as_bytearray()
    try:
        text = bytes(raw_bytes).decode("utf-8")
    except UnicodeDecodeError:
        text = bytes(raw_bytes).decode("latin-1", errors="replace")

    result = analyze_email(text[:MAX_TEXT_LEN])
    await update.message.reply_text(_format_result(result), parse_mode=ParseMode.MARKDOWN)


def main() -> None:
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        raise SystemExit(
            "TELEGRAM_BOT_TOKEN не задан. Установите переменную окружения перед запуском бота."
        )

    application = Application.builder().token(token).build()
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    logger.info("Phishing Scanner bot started")
    application.run_polling()


if __name__ == "__main__":
    main()
