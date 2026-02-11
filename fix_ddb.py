import sqlite3

def fix_database():
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    
    try:
        # Проверяем, существует ли колонка ip_address
        cursor.execute("PRAGMA table_info(page_views)")
        columns = cursor.fetchall()
        column_names = [col[1] for col in columns]
        
        if 'ip_address' not in column_names:
            print("Добавляем колонку ip_address в таблицу page_views...")
            cursor.execute("ALTER TABLE page_views ADD COLUMN ip_address TEXT")
            print("✅ Колонка добавлена успешно")
        else:
            print("✅ Колонка ip_address уже существует")
            
        # Также проверяем другие таблицы
        cursor.execute("PRAGMA table_info(property_views)")
        columns = cursor.fetchall()
        column_names = [col[1] for col in columns]
        
        if 'ip_address' not in column_names:
            print("Добавляем колонку ip_address в таблицу property_views...")
            cursor.execute("ALTER TABLE property_views ADD COLUMN ip_address TEXT")
            print("✅ Колонка добавлена успешно")
        else:
            print("✅ Колонка ip_address уже существует в property_views")
            
        # Добавляем колонку tx_hash в crypto_invoices если её нет
        cursor.execute("PRAGMA table_info(crypto_invoices)")
        columns = cursor.fetchall()
        column_names = [col[1] for col in columns]
        
        if 'tx_hash' not in column_names:
            print("Добавляем колонку tx_hash в таблицу crypto_invoices...")
            cursor.execute("ALTER TABLE crypto_invoices ADD COLUMN tx_hash TEXT")
            print("✅ Колонка tx_hash добавлена успешно")
        else:
            print("✅ Колонка tx_hash уже существует")
            
        conn.commit()
        print("✅ База данных обновлена успешно!")
        
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    fix_database()