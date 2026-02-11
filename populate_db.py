import sqlite3
import json
import bcrypt

# Подключение к базе данных
conn = sqlite3.connect('turkey_realty.db')
cursor = conn.cursor()

# Удаляем существующие таблицы чтобы создать новые (опционально)
cursor.execute("DROP TABLE IF EXISTS users")
cursor.execute("DROP TABLE IF EXISTS properties")
cursor.execute("DROP TABLE IF EXISTS favorites")
cursor.execute("DROP TABLE IF EXISTS transactions")

# Создание таблиц
cursor.execute('''
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT NOT NULL,
        phone TEXT,
        role TEXT DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')

# Создаем админа с хешированным паролем
admin_password = "admin123"
hashed_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

cursor.execute("""
    INSERT INTO users (email, password, name, phone, role) 
    VALUES (?, ?, ?, ?, ?)
""", ('admin@test.com', hashed_password, 'Админ', '+68686884845', 'admin'))

cursor.execute('''
    CREATE TABLE properties (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        property_type TEXT NOT NULL,
        deal_type TEXT NOT NULL,
        price REAL NOT NULL,
        city TEXT NOT NULL,
        district TEXT NOT NULL,
        address TEXT,
        rooms TEXT,
        area REAL,
        floor INTEGER,
        total_floors INTEGER,
        year_built INTEGER,
        latitude REAL,
        longitude REAL,
        images TEXT,
        status TEXT DEFAULT 'available',
        amenities TEXT,
        views INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
''')

cursor.execute('''
    CREATE TABLE favorites (
        user_id INTEGER,
        property_id INTEGER,
        PRIMARY KEY (user_id, property_id),
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (property_id) REFERENCES properties (id)
    )
''')

cursor.execute('''
    CREATE TABLE transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        property_id INTEGER,
        amount REAL,
        currency TEXT,
        status TEXT,
        wallet_address TEXT,
        tx_hash TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (property_id) REFERENCES properties (id)
    )
''')

# Создаем остальные таблицы из основного приложения
cursor.execute('''
    CREATE TABLE IF NOT EXISTS crypto_wallet_config (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        wallet_address TEXT NOT NULL,
        currency TEXT DEFAULT 'USDT',
        network TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        property_id INTEGER,
        amount REAL NOT NULL,
        currency TEXT DEFAULT 'USD',
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (property_id) REFERENCES properties (id)
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS crypto_invoices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        crypto_address TEXT NOT NULL,
        amount REAL NOT NULL,
        currency TEXT DEFAULT 'USDT',
        status TEXT DEFAULT 'pending',
        tx_hash TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        confirmed_at TIMESTAMP,
        FOREIGN KEY (order_id) REFERENCES orders (id)
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS payment_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER,
        invoice_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (order_id) REFERENCES orders (id),
        FOREIGN KEY (invoice_id) REFERENCES crypto_invoices (id)
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS admin_audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        entity_type TEXT,
        entity_id INTEGER,
        details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (admin_id) REFERENCES users (id)
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS page_views (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        path TEXT,
        user_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
''')

# Примеры недвижимости
properties = [
    {
        "title": "Роскошная квартира с видом на Босфор",
        "description": "Современная квартира в престижном районе Стамбула с панорамным видом на пролив Босфор. Высококачественная отделка, просторная планировка, близость к инфраструктуре.",
        "property_type": "apartment",
        "deal_type": "sale",
        "price": 450000,
        "city": "istanbul",
        "district": "Бешикташ",
        "address": "Бешикташ, ул. Босфор, 45",
        "rooms": "3+1",
        "area": 165,
        "floor": 8,
        "total_floors": 12,
        "year_built": 2022,
        "latitude": 41.0422,
        "longitude": 29.0078,
        "images": json.dumps(["/static/images/4Eaa6DysGCj9.jpg", "/static/images/YPSzDR0B1qDE.jpg", "/static/images/UiQHrKydbRsG.jpg"]),
        "amenities": json.dumps(["Бассейн", "Фитнес-центр", "Парковка", "Охрана 24/7", "Лифт", "Балкон"])
    },
    {
        "title": "Вилла у моря в Анталье",
        "description": "Потрясающая вилла с частным бассейном в 100 метрах от пляжа. Идеальное место для семейного отдыха и инвестиций в туристическую недвижимость.",
        "property_type": "villa",
        "deal_type": "sale",
        "price": 850000,
        "city": "antalya",
        "district": "Лара",
        "address": "Лара, Морская улица, 12",
        "rooms": "5+1",
        "area": 320,
        "floor": 1,
        "total_floors": 2,
        "year_built": 2021,
        "latitude": 36.8569,
        "longitude": 30.7854,
        "images": json.dumps(["/static/images/bbBFNl25Vxsw.jpg", "/static/images/vgNAxjhHOc9l.webp", "/static/images/6EXJsDRj5QaL.jpg"]),
        "amenities": json.dumps(["Частный бассейн", "Сад", "Барбекю", "Парковка на 3 авто", "Сауна", "Терраса"])
    },
    {
        "title": "Современная квартира в центре Аланьи",
        "description": "Новая квартира в современном комплексе с развитой инфраструктурой. Отличный вариант для постоянного проживания или сдачи в аренду.",
        "property_type": "apartment",
        "deal_type": "sale",
        "price": 120000,
        "city": "alanya",
        "district": "Махмутлар",
        "address": "Махмутлар, Центральная улица, 78",
        "rooms": "2+1",
        "area": 95,
        "floor": 5,
        "total_floors": 9,
        "year_built": 2023,
        "latitude": 36.4988,
        "longitude": 32.0051,
        "images": json.dumps(["/static/images/YPSzDR0B1qDE.jpg", "/static/images/UiQHrKydbRsG.jpg", "/static/images/4Eaa6DysGCj9.jpg"]),
        "amenities": json.dumps(["Бассейн", "Тренажерный зал", "Детская площадка", "Парковка", "Генератор"])
    },
    {
        "title": "Пентхаус с террасой в Бодруме",
        "description": "Эксклюзивный пентхаус с огромной террасой и видом на Эгейское море. Премиальная отделка, smart home система, закрытая территория.",
        "property_type": "apartment",
        "deal_type": "sale",
        "price": 680000,
        "city": "bodrum",
        "district": "Центр",
        "address": "Бодрум, Морской бульвар, 23",
        "rooms": "4+1",
        "area": 240,
        "floor": 10,
        "total_floors": 10,
        "year_built": 2022,
        "latitude": 37.0344,
        "longitude": 27.4305,
        "images": json.dumps(["/static/images/jv2pTgj69h23.jpg", "/static/images/Xd823lltTemJ.webp", "/static/images/4Eaa6DysGCj9.jpg"]),
        "amenities": json.dumps(["Терраса 150м²", "Джакузи", "Smart Home", "Консьерж", "Подземная парковка", "Винный погреб"])
    },
    {
        "title": "Уютная квартира для аренды в Измире",
        "description": "Полностью меблированная квартира в тихом районе Измира. Идеально подходит для долгосрочной аренды, рядом школы, магазины и транспорт.",
        "property_type": "apartment",
        "deal_type": "rent",
        "price": 800,
        "city": "izmir",
        "district": "Алсанджак",
        "address": "Алсанджак, ул. Кордон, 156",
        "rooms": "2+1",
        "area": 85,
        "floor": 3,
        "total_floors": 5,
        "year_built": 2018,
        "latitude": 38.4237,
        "longitude": 27.1428,
        "images": json.dumps(["/static/images/UiQHrKydbRsG.jpg", "/static/images/YPSzDR0B1qDE.jpg", "/static/images/4Eaa6DysGCj9.jpg"]),
        "amenities": json.dumps(["Мебель", "Бытовая техника", "Кондиционер", "Интернет", "Балкон"])
    },
    {
        "title": "Вилла с бассейном в Мармарисе",
        "description": "Великолепная вилла в окружении соснового леса с видом на море. Частный бассейн, ухоженный сад, тихое место для отдыха.",
        "property_type": "villa",
        "deal_type": "sale",
        "price": 520000,
        "city": "marmaris",
        "district": "Ичмелер",
        "address": "Ичмелер, Горная улица, 34",
        "rooms": "4+1",
        "area": 280,
        "floor": 1,
        "total_floors": 2,
        "year_built": 2020,
        "latitude": 36.7456,
        "longitude": 28.2336,
        "images": json.dumps(["/static/images/6EXJsDRj5QaL.jpg", "/static/images/bbBFNl25Vxsw.jpg", "/static/images/vgNAxjhHOc9l.webp"]),
        "amenities": json.dumps(["Бассейн", "Сад", "Барбекю зона", "Парковка", "Кондиционеры", "Камин"])
    },
    {
        "title": "Студия в новом комплексе Аланьи",
        "description": "Компактная студия в современном комплексе с отличной инфраструктурой. Идеально для инвестиций и сдачи в аренду туристам.",
        "property_type": "apartment",
        "deal_type": "sale",
        "price": 65000,
        "city": "alanya",
        "district": "Оба",
        "address": "Оба, ул. Ататюрка, 234",
        "rooms": "1+1",
        "area": 45,
        "floor": 2,
        "total_floors": 7,
        "year_built": 2024,
        "latitude": 36.5447,
        "longitude": 31.9812,
        "images": json.dumps(["/static/images/YPSzDR0B1qDE.jpg", "/static/images/4Eaa6DysGCj9.jpg", "/static/images/UiQHrKydbRsG.jpg"]),
        "amenities": json.dumps(["Бассейн", "Фитнес", "Сауна", "Парковка", "Охрана"])
    },
    {
        "title": "Коммерческое помещение в центре Стамбула",
        "description": "Отличное коммерческое помещение в оживленном районе Стамбула. Подходит для магазина, офиса или ресторана. Высокий трафик.",
        "property_type": "commercial",
        "deal_type": "rent",
        "price": 3500,
        "city": "istanbul",
        "district": "Шишли",
        "address": "Шишли, Торговая улица, 89",
        "rooms": None,
        "area": 120,
        "floor": 1,
        "total_floors": 1,
        "year_built": 2015,
        "latitude": 41.0602,
        "longitude": 28.9887,
        "images": json.dumps(["/static/images/4Eaa6DysGCj9.jpg", "/static/images/YPSzDR0B1qDE.jpg", "/static/images/UiQHrKydbRsG.jpg"]),
        "amenities": json.dumps(["Витрина", "Парковка", "Охрана", "Кондиционер", "Санузел"])
    },
    {
        "title": "Апартаменты с видом на море в Фетхие",
        "description": "Прекрасные апартаменты с панорамным видом на Средиземное море. Закрытая территория, бассейн, близость к пляжу.",
        "property_type": "apartment",
        "deal_type": "sale",
        "price": 195000,
        "city": "fethiye",
        "district": "Чалыш",
        "address": "Чалыш, Пляжная улица, 67",
        "rooms": "2+1",
        "area": 110,
        "floor": 4,
        "total_floors": 6,
        "year_built": 2021,
        "latitude": 36.6226,
        "longitude": 29.1161,
        "images": json.dumps(["/static/images/UiQHrKydbRsG.jpg", "/static/images/bbBFNl25Vxsw.jpg", "/static/images/6EXJsDRj5QaL.jpg"]),
        "amenities": json.dumps(["Бассейн", "Парковка", "Лифт", "Охрана", "Детская площадка", "Балкон"])
    },
    {
        "title": "Роскошная вилла в Кушадасы",
        "description": "Элитная вилла премиум-класса с собственным выходом к морю. Дизайнерский ремонт, умный дом, все для комфортной жизни.",
        "property_type": "villa",
        "deal_type": "sale",
        "price": 1200000,
        "city": "kusadasi",
        "district": "Центр",
        "address": "Кушадасы, Прибрежная улица, 5",
        "rooms": "6+2",
        "area": 450,
        "floor": 1,
        "total_floors": 3,
        "year_built": 2023,
        "latitude": 37.8587,
        "longitude": 27.2614,
        "images": json.dumps(["/static/images/6EXJsDRj5QaL.jpg", "/static/images/jv2pTgj69h23.jpg", "/static/images/Xd823lltTemJ.webp"]),
        "amenities": json.dumps(["Частный пляж", "Бассейн", "Спа", "Тренажерный зал", "Гараж", "Smart Home", "Сауна", "Винный погреб"])
    },
    {
        "title": "Квартира в новостройке Анкары",
        "description": "Современная квартира в новом жилом комплексе столицы. Развитая инфраструктура, удобная транспортная доступность.",
        "property_type": "apartment",
        "deal_type": "sale",
        "price": 180000,
        "city": "ankara",
        "district": "Чанкая",
        "address": "Чанкая, проспект Республики, 145",
        "rooms": "3+1",
        "area": 135,
        "floor": 7,
        "total_floors": 15,
        "year_built": 2023,
        "latitude": 39.9208,
        "longitude": 32.8541,
        "images": json.dumps(["/static/images/4Eaa6DysGCj9.jpg", "/static/images/YPSzDR0B1qDE.jpg", "/static/images/UiQHrKydbRsG.jpg"]),
        "amenities": json.dumps(["Бассейн", "Фитнес", "Парковка", "Детский сад", "Охрана 24/7", "Лифт"])
    },
    {
        "title": "Вилла для аренды в Бурсе",
        "description": "Уютная вилла для долгосрочной аренды в зеленом районе Бурсы. Сад, парковка, тихое место вдали от городской суеты.",
        "property_type": "villa",
        "deal_type": "rent",
        "price": 2500,
        "city": "bursa",
        "district": "Нилюфер",
        "address": "Нилюфер, Садовая улица, 23",
        "rooms": "4+1",
        "area": 250,
        "floor": 1,
        "total_floors": 2,
        "year_built": 2019,
        "latitude": 40.2669,
        "longitude": 28.9948,
        "images": json.dumps(["/static/images/bbBFNl25Vxsw.jpg", "/static/images/6EXJsDRj5QaL.jpg", "/static/images/vgNAxjhHOc9l.webp"]),
        "amenities": json.dumps(["Сад", "Парковка", "Барбекю", "Камин", "Кондиционеры", "Мебель"])
    }
]

# Добавление объектов в базу данных
for prop in properties:
    cursor.execute('''
        INSERT INTO properties (
            title, description, property_type, deal_type, price,
            city, district, address, rooms, area, floor, total_floors,
            year_built, latitude, longitude, images, amenities, user_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        prop["title"],
        prop["description"],
        prop["property_type"],
        prop["deal_type"],
        prop["price"],
        prop["city"],
        prop["district"],
        prop["address"],
        prop["rooms"],
        prop["area"],
        prop["floor"],
        prop["total_floors"],
        prop["year_built"],
        prop["latitude"],
        prop["longitude"],
        prop["images"],
        prop["amenities"],
        1  # user_id (админ)
    ))

conn.commit()

# Создаем обычного пользователя для теста
user_password = "user123"
user_hashed = bcrypt.hashpw(user_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
cursor.execute("""
    INSERT INTO users (email, password, name, phone, role) 
    VALUES (?, ?, ?, ?, ?)
""", ('user@test.com', user_hashed, 'Пользователь Тест', '+79990001122', 'user'))

conn.commit()
conn.close()

print("✅ База данных успешно создана!")
print("\nДанные для входа:")
print("1. Администратор:")
print("   Email: admin@test.com")
print("   Пароль: admin123")
print("   Ссылка: http://localhost:8000/admin-panel")
print("\n2. Обычный пользователь:")
print("   Email: user@test.com")
print("   Пароль: user123")
print("\n3. Тестовый кошелек для платежей (опционально):")
print("   USDT (TRC20): TYJxG8KjCqA8S7gLsF6Rk5M9oV2N3P4Q5")
print("\nЗапустите приложение: python main.py")