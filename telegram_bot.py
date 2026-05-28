#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
АГРОТЕП — Telegram ANPR Bot
Запуск: python3 bot.py
Налаштування: файл .env поруч з ботом
"""

import os, re, logging, shutil
from typing import Optional
from datetime import datetime
from dotenv import load_dotenv

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler,
    ContextTypes, ConversationHandler, MessageHandler, filters
)

# ── Завантажуємо .env ────────────────────────────────────────────
load_dotenv()

TG_TOKEN  = os.environ.get('TG_TOKEN',  '')   # токен бота
GROUP_ID  = int(os.environ.get('GROUP_ID', '0'))  # ID групи (від'ємне число)
ADMIN_IDS = set(                               # ID адмінів для особистих повідомлень
    int(x) for x in os.environ.get('ADMIN_IDS', '').split(',') if x.strip()
)

ROOT           = os.environ.get('ROOT', '/home/bcsftp')
WHITELIST_FILE = os.path.join(ROOT, 'whitelist.txt')
BACKUP_FILE    = os.path.join(ROOT, 'whitelist.bak')
AUDIT_LOG      = os.path.join(ROOT, 'audit.log')

# ── Стан для ConversationHandler ────────────────────────────────
WAIT_CATEGORY, WAIT_NOTE = range(2)

# ── Логування ───────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
log = logging.getLogger(__name__)

processed_files: set = set()

# Простий кеш для scan_all_events (TTL = 4 сек)
_events_cache: list = []
_events_cache_ts: float = 0.0

# ════════════════════════════════════════════════════════════════
# ДОПОМІЖНІ ФУНКЦІЇ
# ════════════════════════════════════════════════════════════════

def audit(action: str, detail: str = ""):
    try:
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(AUDIT_LOG, 'a', encoding='utf-8') as f:
            f.write(f"[{ts}] BOT | {action} | {detail}\n")
    except Exception:
        pass


def normalize_plate(p: str) -> str:
    if not p:
        return ""
    trans = str.maketrans("АВЕКМНОРСТХІ", "ABEKMHOPCTXI")
    return p.upper().translate(trans).replace(" ", "")


def load_whitelist() -> dict:
    base = {}
    if os.path.isfile(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    if '|' in line:
                        p, n = line.strip().split('|', 1)
                        base[normalize_plate(p)] = n.strip()
        except Exception as e:
            log.error(f"load_whitelist error: {e}")
    return base


def save_whitelist(base: dict):
    if os.path.exists(WHITELIST_FILE):
        shutil.copy2(WHITELIST_FILE, BACKUP_FILE)
    with open(WHITELIST_FILE, 'w', encoding='utf-8') as f:
        for p, n in base.items():
            f.write(f"{p}|{n}\n")


def find_similar(plate: str, base: dict, max_dist: int = 1) -> Optional[str]:
    """Fuzzy matching — шукає номер з похибкою 1 символ."""
    norm = normalize_plate(plate)
    if len(norm) < 6:
        return None
    for ref in base:
        if len(norm) != len(ref):
            continue
        if sum(a != b for a, b in zip(norm, ref)) <= max_dist:
            return ref
    return None


def format_duration(td) -> str:
    ts = int(td.total_seconds())
    if ts <= 60:
        return "щойно"
    d, h, m = ts // 86400, (ts % 86400) // 3600, (ts % 3600) // 60
    parts = []
    if d: parts.append(f"{d}д")
    if h: parts.append(f"{h}г")
    parts.append(f"{m}хв")
    return " ".join(parts)


def get_cat_icon(note: str) -> str:
    if "[Т]" in note: return "🚛"
    if "[С]" in note: return "🚗"
    if "[Л]" in note: return "🛠️"
    if "[Р]" in note: return "👤"
    if "[Ч]" in note: return "🚫"
    return "⚠️"


def clean_note(note: str) -> str:
    for tag in ('[Т] ', '[С] ', '[Л] ', '[Р] ', '[Ч] ',
                '[Т]',  '[С]',  '[Л]',  '[Р]',  '[Ч]'):
        note = note.replace(tag, '')
    return note.strip()


def scan_all_events(use_cache: bool = True) -> list:
    """Сканує всі три папки, повертає список подій відсортований за часом."""
    global _events_cache, _events_cache_ts
    import time
    if use_cache and (time.time() - _events_cache_ts) < 4.0:
        return _events_cache
    events = []
    for sub in ('enter', 'exit', 'pit'):
        path = os.path.join(ROOT, sub)
        if not os.path.isdir(path):
            continue
        for f in os.listdir(path):
            if not f.lower().endswith('.jpg') or '.plate.' in f:
                continue
            m = re.match(r'(\d{4}-\d{2}-\d{2})_(\d{2}-\d{2})', f)
            pm = re.search(r'_([A-Z0-9А-ЯІ]+)\.jpg$', f, re.IGNORECASE)
            if m and pm:
                try:
                    dt = datetime.strptime(f"{m.group(1)} {m.group(2).replace('-',':')}", "%Y-%m-%d %H:%M")
                    events.append({
                        'file': f, 'subdir': sub, 'dt': dt,
                        'plate': pm.group(1).upper(),
                        'norm': normalize_plate(pm.group(1)),
                        'path': os.path.join(path, f),
                    })
                except Exception:
                    continue
    events.sort(key=lambda x: x['dt'])
    _events_cache = events
    _events_cache_ts = __import__('time').time()
    return events


def get_inside_status() -> dict:
    """Повертає dict {norm_plate: last_event} де last_event — в enter/pit."""
    events = scan_all_events()
    status = {}
    for e in events:
        status[e['norm']] = e
    return {p: e for p, e in status.items() if e['subdir'] in ('enter', 'pit')}


def get_entry_time(norm_plate: str) -> Optional[datetime]:
    """Знаходить час останнього заїзду конкретного авто."""
    events = scan_all_events()
    last_enter = None
    for e in events:
        if e['norm'] == norm_plate and e['subdir'] in ('enter', 'pit'):
            last_enter = e['dt']
        elif e['norm'] == norm_plate and e['subdir'] == 'exit':
            last_enter = None  # виїхав — обнуляємо
    return last_enter


# ════════════════════════════════════════════════════════════════
# ОСНОВНИЙ МОНІТОРИНГ
# ════════════════════════════════════════════════════════════════

async def global_monitor(context: ContextTypes.DEFAULT_TYPE):
    base = load_whitelist()

    for sub in ('enter', 'exit', 'pit'):
        path = os.path.join(ROOT, sub)
        if not os.path.isdir(path):
            continue

        files = sorted(
            f for f in os.listdir(path)
            if f.lower().endswith('.jpg') and '.plate.' not in f
        )

        for fname in files:
            if fname in processed_files:
                continue

            try:
                fpath = os.path.join(path, fname)

                # Ігноруємо файли старше 5 хв при старті
                age = datetime.now().timestamp() - os.path.getmtime(fpath)
                if age > 300:
                    processed_files.add(fname)
                    continue

                pm = re.search(r'_([A-Z0-9А-ЯІ]+)\.jpg$', fname, re.IGNORECASE)
                plate = pm.group(1).upper() if pm else "???"
                norm  = normalize_plate(plate)

                # Шукаємо в базі (пряме + fuzzy)
                note = base.get(norm)
                matched_norm = norm
                fuzzy_match = False
                if note is None:
                    sim = find_similar(norm, base)
                    if sim:
                        note = base[sim]
                        matched_norm = sim
                        fuzzy_match = True

                is_unknown = note is None
                if is_unknown:
                    note = ""

                icon = get_cat_icon(note) if not is_unknown else "⚠️"
                is_blacklist = "[Ч]" in note

                # Напрямок
                if sub == 'exit':
                    direction = "❌ ВИЇЗД"
                elif sub == 'pit':
                    direction = "✅ ЗАЇЗД (ЯМА)"
                else:
                    direction = "✅ ЗАЇЗД"

                owner = clean_note(note) if not is_unknown else "Немає в базі"
                fuzzy_hint = f" ≈ `{matched_norm}`" if fuzzy_match else ""

                # Формуємо текст
                lines = [
                    f"*{direction}*",
                    f"Номер: `{plate}` {icon}{fuzzy_hint}",
                    f"Власник: {owner}",
                ]

                if sub == 'exit':
                    entry_dt = get_entry_time(norm)
                    if entry_dt:
                        dur = format_duration(datetime.now() - entry_dt)
                        lines.append(f"⏱ Пробув: {dur}")

                if is_blacklist:
                    lines.insert(0, "🚨 *УВАГА! ЧОРНИЙ СПИСОК!*")

                caption = "\n".join(lines)

                # Кнопка "Додати в базу" — тільки для невідомих, в особисті адмінам
                if is_unknown:
                    keyboard = InlineKeyboardMarkup([[
                        InlineKeyboardButton(
                            "➕ Додати в базу",
                            callback_data=f"add:{plate}"
                        )
                    ]])
                else:
                    keyboard = None

                # Надсилаємо в групу
                with open(fpath, 'rb') as photo:
                    await context.bot.send_photo(
                        chat_id=GROUP_ID,
                        photo=photo,
                        caption=caption,
                        parse_mode='Markdown',
                        reply_markup=None,  # в групі кнопки немає
                    )

                # Якщо невідомий — дублюємо адмінам в особисті з кнопкою
                if is_unknown and ADMIN_IDS:
                    for admin_id in ADMIN_IDS:
                        try:
                            with open(fpath, 'rb') as photo:
                                await context.bot.send_photo(
                                    chat_id=admin_id,
                                    photo=photo,
                                    caption=caption + "\n\n_Натисніть кнопку щоб додати в базу_",
                                    parse_mode='Markdown',
                                    reply_markup=keyboard,
                                )
                        except Exception as e:
                            log.warning(f"Cannot send to admin {admin_id}: {e}")

                # Якщо чорний список — окремий алерт в групу
                if is_blacklist:
                    await context.bot.send_message(
                        chat_id=GROUP_ID,
                        text=f"🚨 *ТРИВОГА!* Авто з чорного списку на території!\nНомер: `{plate}`\nВласник: {owner}",
                        parse_mode='Markdown',
                    )

                processed_files.add(fname)
                if len(processed_files) > 50000: processed_files.clear()
                audit('BOT_NOTIFY', f"{sub} {fname}")

            except Exception as e:
                log.error(f"Error processing {fname}: {e}")
                processed_files.add(fname)


# ════════════════════════════════════════════════════════════════
# ANTI-OVERSTAY — раз на годину
# ════════════════════════════════════════════════════════════════

async def overstay_check(context: ContextTypes.DEFAULT_TYPE):
    """Сповіщення якщо авто (не тягач) більше 24г на території."""
    base = load_whitelist()
    inside = get_inside_status()
    now = datetime.now()
    alerts = []

    for norm, event in inside.items():
        diff = now - event['dt']
        if diff.total_seconds() < 86400:
            continue
        note = base.get(norm, "")
        if not note:
            sim = find_similar(norm, base)
            if sim:
                note = base[sim]
        if "[Т]" in note:   # тягачі не враховуємо
            continue
        owner = clean_note(note) if note else "Невідомий"
        dur = format_duration(diff)
        icon = get_cat_icon(note) if note else "⚠️"
        alerts.append(f"{icon} `{event['plate']}` — {owner}\n└ ⏰ На території: *{dur}*")

    if alerts:
        header = f"⏰ *Авто на території більше 24 годин ({len(alerts)} шт):*\n\n"
        text = header + "\n\n".join(alerts)
        await context.bot.send_message(
            chat_id=GROUP_ID,
            text=text,
            parse_mode='Markdown',
        )
        audit('OVERSTAY_ALERT', f"{len(alerts)} vehicles")


# ════════════════════════════════════════════════════════════════
# CALLBACK: ДОДАТИ В БАЗУ (кнопка під фото)
# ════════════════════════════════════════════════════════════════

async def cb_add_to_base(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()

    if not ADMIN_IDS or query.from_user.id not in ADMIN_IDS:
        await query.edit_message_reply_markup(reply_markup=None)
        await query.message.reply_text("⛔ Немає доступу.")
        return ConversationHandler.END

    plate = query.data.split(':', 1)[1]
    context.user_data['add_plate'] = normalize_plate(plate)

    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🚛 Тягач",       callback_data="cat:Т"),
            InlineKeyboardButton("🚗 Співробітник", callback_data="cat:С"),
        ],
        [
            InlineKeyboardButton("🛠️ Службове",    callback_data="cat:Л"),
            InlineKeyboardButton("👤 Інше",         callback_data="cat:Р"),
        ],
        [
            InlineKeyboardButton("🚫 Чорний список", callback_data="cat:Ч"),
        ],
    ])
    await query.edit_message_reply_markup(reply_markup=None)
    await query.message.reply_text(
        f"Додаємо *{plate}*\nОберіть категорію:",
        parse_mode='Markdown',
        reply_markup=keyboard,
    )
    return WAIT_CATEGORY


async def cb_category_chosen(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()

    cat = query.data.split(':', 1)[1]
    context.user_data['add_cat'] = cat

    await query.edit_message_reply_markup(reply_markup=None)
    await query.message.reply_text(
        "Введіть прізвище або назву (або — для пропуску):"
    )
    return WAIT_NOTE


async def cb_note_received(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    note_text = update.message.text.strip()
    if note_text == '—' or note_text == '-':
        note_text = ''

    plate = context.user_data.get('add_plate', '')
    cat   = context.user_data.get('add_cat', 'Р')

    base = load_whitelist()
    base[plate] = f"[{cat}] {note_text}".strip() if note_text else f"[{cat}]"
    save_whitelist(base)
    audit('BASE_ADD_BOT', f"{plate} [{cat}] {note_text}")

    cat_names = {'Т': 'Тягач', 'С': 'Співробітник', 'Л': 'Службове', 'Р': 'Інше', 'Ч': 'Чорний список'}
    await update.message.reply_text(
        f"✅ *{plate}* додано в базу\nКатегорія: {cat_names.get(cat, cat)}\nПримітка: {note_text or '—'}",
        parse_mode='Markdown',
    )
    return ConversationHandler.END


async def cb_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text("Скасовано.")
    return ConversationHandler.END


# ════════════════════════════════════════════════════════════════
# КОМАНДИ
# ════════════════════════════════════════════════════════════════

async def cmd_inside(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Список авто на території — /inside"""
    base   = load_whitelist()
    inside = get_inside_status()
    now    = datetime.now()

    if not inside:
        await update.message.reply_text("🟢 На території порожньо.")
        return

    lines = []
    for norm, event in inside.items():
        note  = base.get(norm) or ""
        if not note:
            sim = find_similar(norm, base)
            if sim:
                note = base[sim]
        owner = clean_note(note) if note else "Невідомий"
        icon  = get_cat_icon(note) if note else "⚠️"
        dur   = format_duration(now - event['dt'])
        lines.append(f"{icon} `{event['plate']}` — {owner}\n└ ⏱ {dur}")

    header = f"📍 *На території зараз ({len(lines)} авто):*\n\n"
    # Розбиваємо на частини якщо повідомлення занадто довге (ліміт Telegram 4096)
    chunks = []
    current = header
    for line in lines:
        addition = line + "\n\n"
        if len(current) + len(addition) > 3800:
            chunks.append(current.rstrip())
            current = addition
        else:
            current += addition
    if current.strip():
        chunks.append(current.rstrip())

    for chunk in chunks:
        await update.message.reply_text(chunk, parse_mode='Markdown')


async def cmd_summary(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Статистика за сьогодні — /summary"""
    today  = datetime.now().strftime('%Y-%m-%d')
    events = scan_all_events()
    today_events = [e for e in events if e['dt'].strftime('%Y-%m-%d') == today]

    en_c  = sum(1 for e in today_events if e['subdir'] in ('enter', 'pit'))
    ex_c  = sum(1 for e in today_events if e['subdir'] == 'exit')
    on_t  = len(get_inside_status())
    base  = load_whitelist()
    unk_c = sum(1 for e in today_events if e['norm'] not in base and find_similar(e['norm'], base) is None)

    text = (
        f"📊 *Статистика за {today}:*\n\n"
        f"📥 Заїхало: *{en_c}*\n"
        f"📤 Виїхало: *{ex_c}*\n"
        f"🏠 На території: *{on_t}*\n"
        f"❓ Невідомих: *{unk_c}*"
    )
    await update.message.reply_text(text, parse_mode='Markdown')


async def cmd_who(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Пошук по базі — /who AA1234BB"""
    if not context.args:
        await update.message.reply_text("Використання: /who *НОМЕР*", parse_mode='Markdown')
        return

    plate = normalize_plate(" ".join(context.args))
    base  = load_whitelist()

    note = base.get(plate)
    matched = plate
    fuzzy = False

    if note is None:
        sim = find_similar(plate, base)
        if sim:
            note = base[sim]
            matched = sim
            fuzzy = True

    if note:
        owner = clean_note(note)
        icon  = get_cat_icon(note)
        cat_names = {'[Т]': 'Тягач', '[С]': 'Співробітник', '[Л]': 'Службове', '[Р]': 'Інше', '[Ч]': 'Чорний список'}
        cat_label = next((v for k, v in cat_names.items() if k in note), 'Невідомо')

        # Перевіряємо чи зараз на території
        inside = get_inside_status()
        status = "🟢 На території" if matched in inside else "🔴 Відсутній"
        if matched in inside:
            dur = format_duration(datetime.now() - inside[matched]['dt'])
            status += f" ({dur})"

        fuzzy_hint = f"\n_Знайдено за схожістю: `{matched}`_" if fuzzy else ""
        text = (
            f"{icon} *{plate}*{fuzzy_hint}\n"
            f"Власник: {owner}\n"
            f"Категорія: {cat_label}\n"
            f"Статус: {status}"
        )
    else:
        text = f"❓ `{plate}` — не знайдено в базі."

    await update.message.reply_text(text, parse_mode='Markdown')


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "🤖 *АГРОТЕП ANPR Бот*\n\n"
        "/inside — список авто на території\n"
        "/summary — статистика за сьогодні\n"
        "/who НОМЕР — пошук по базі\n"
        "/help — ця довідка"
    )
    await update.message.reply_text(text, parse_mode='Markdown')


# ════════════════════════════════════════════════════════════════
# ЗАПУСК
# ════════════════════════════════════════════════════════════════

def main():
    if not TG_TOKEN:
        raise ValueError("TG_TOKEN не встановлено у .env файлі!")
    if not GROUP_ID:
        raise ValueError("GROUP_ID не встановлено у .env файлі!")

    # Індексуємо існуючі файли щоб не надсилати старі при старті
    for sub in ('enter', 'exit', 'pit'):
        p = os.path.join(ROOT, sub)
        if os.path.isdir(p):
            for f in os.listdir(p):
                processed_files.add(f)
    log.info(f"Проіндексовано {len(processed_files)} існуючих файлів")

    app = Application.builder().token(TG_TOKEN).build()

    # ConversationHandler для "Додати в базу"
    add_conv = ConversationHandler(
        entry_points=[CallbackQueryHandler(cb_add_to_base, pattern=r'^add:')],
        states={
            WAIT_CATEGORY: [CallbackQueryHandler(cb_category_chosen, pattern=r'^cat:')],
            WAIT_NOTE:     [MessageHandler(filters.TEXT & ~filters.COMMAND, cb_note_received)],
        },
        fallbacks=[CommandHandler('cancel', cb_cancel)],
        per_user=True,
        per_chat=False,
    )

    app.add_handler(add_conv)
    app.add_handler(CommandHandler("inside",  cmd_inside))
    app.add_handler(CommandHandler("summary", cmd_summary))
    app.add_handler(CommandHandler("who",     cmd_who))
    app.add_handler(CommandHandler("help",    cmd_help))
    app.add_handler(CommandHandler("start",   cmd_help))

    # Моніторинг кожні 5 сек
    app.job_queue.run_repeating(global_monitor, interval=5, first=2)

    # Anti-overstay — кожну годину
    app.job_queue.run_repeating(overstay_check, interval=3600, first=60)

    log.info("АГРОТЕП ANPR бот запущено")
    app.run_polling(drop_pending_updates=True)


if __name__ == '__main__':
    main()
