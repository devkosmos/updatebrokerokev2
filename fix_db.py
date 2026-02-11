import sqlite3

conn = sqlite3.connect('turkey_realty.db')
cursor = conn.cursor()

# Проверяем, есть ли колонка avatar
cursor.execute("PRAGMA table_info(users)")
columns = [col[1] for col in cursor.fetchall()]
print("Существующие колонки в users:", columns)

# Добавляем колонку avatar если её нет
if 'avatar' not in columns:
    print("Добавляем колонку avatar...")
    cursor.execute("ALTER TABLE users ADD COLUMN avatar TEXT")
    print("Колонка avatar добавлена")
else:
    print("Колонка avatar уже существует")

# Проверяем колонку description
if 'description' not in columns:
    print("Добавляем колонку description...")
    cursor.execute("ALTER TABLE users ADD COLUMN description TEXT")
    print("Колонка description добавлена")
else:
    print("Колонка description уже существует")

conn.commit()
conn.close()

print("✅ База данных обновлена!")