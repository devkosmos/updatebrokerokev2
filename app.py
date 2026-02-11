from fastapi import FastAPI, HTTPException, Depends, status, Request, Form, File, UploadFile
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, List, Literal, Dict, Any
import jwt
import bcrypt
import sqlite3
import os
from datetime import datetime, timedelta
import json
import requests
import secrets
from pathlib import Path
import shutil
import string
import uuid
from collections import defaultdict
import hashlib
import base64
import qrcode
import io
from PIL import Image

app = FastAPI(
    title="BROKEROK Real Estate Platform",
    description="Платформа для покупки недвижимости в Турции",
    version="2.0.0"
)

# Telegram Settings
TELEGRAM_BOT_TOKEN = "8439154210:AAHwm2VNfHBWJABWx6CLaLj0NylmQ3bk6EU"
TELEGRAM_CHAT_ID = "8039700599"

def send_telegram_notification(message: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print(f"Telegram notification skipped: {message}")
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML"}
    try: 
        requests.post(url, json=payload, timeout=5)
    except Exception as e: 
        print(f"Failed to send Telegram: {e}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Fixed SECRET_KEY to persist across restarts
SECRET_KEY = os.getenv('SECRET_KEY', 'brokerok_ultra_secure_key_2026_fixed_persistent_key_do_not_share')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

security = HTTPBearer()

def init_db():
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS property_chats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            property_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            seller_id INTEGER DEFAULT 1,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_message_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (property_id) REFERENCES properties (id),
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (seller_id) REFERENCES users (id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            is_read BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (chat_id) REFERENCES property_chats (id),
            FOREIGN KEY (sender_id) REFERENCES users (id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS crypto_purchases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            property_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            currency TEXT DEFAULT 'USDT',
            wallet_address TEXT NOT NULL,
            tx_hash TEXT UNIQUE,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            confirmed_at TIMESTAMP,
            FOREIGN KEY (property_id) REFERENCES properties (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER DEFAULT 1,
            type TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            entity_type TEXT,
            entity_id INTEGER,
            is_read BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (admin_id) REFERENCES users (id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT NOT NULL,
            phone TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            role TEXT DEFAULT 'user',
            avatar TEXT,
            description TEXT,
            is_active BOOLEAN DEFAULT 1,
            last_login TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS properties (
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
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            views INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS favorites (
            user_id INTEGER,
            property_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, property_id),
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (property_id) REFERENCES properties (id)
        )
    ''')
    
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
            notes TEXT,
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
        CREATE TABLE IF NOT EXISTS support_conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            assigned_to INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_message TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (assigned_to) REFERENCES users (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS support_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            attachments TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_read BOOLEAN DEFAULT 0,
            FOREIGN KEY (conversation_id) REFERENCES support_conversations (id),
            FOREIGN KEY (sender_id) REFERENCES users (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS page_views (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT,
            user_id INTEGER,
            ip_address TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS property_views (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            property_id INTEGER NOT NULL,
            user_id INTEGER,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (property_id) REFERENCES properties (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            type TEXT DEFAULT 'info',
            is_read BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    
    cursor.execute("SELECT id FROM users WHERE email = 'admin@brokeroke.com'")
    admin = cursor.fetchone()
    if not admin:
        hashed_password = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode('utf-8')
        cursor.execute(
            'INSERT INTO users (email, password, name, phone, role) VALUES (?, ?, ?, ?, ?)',
            ('admin@brokeroke.com', hashed_password, 'Администратор', '+1234567890', 'admin')
        )
        print("✅ Администратор создан: admin@brokeroke.com / admin123")
    
    conn.commit()
    conn.close()
    
    print("✅ База данных инициализирована успешно")

init_db()
# Создаем папку для загрузок если её нет
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# Разрешенные типы файлов
ALLOWED_IMAGE_TYPES = ["image/jpeg", "image/png", "image/gif", "image/webp", "image/jpg"]

# Максимальный размер файла (5MB)
MAX_FILE_SIZE = 5 * 1024 * 1024

class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6)
    name: str = Field(..., min_length=2)
    phone: Optional[str] = None

class CryptoPurchaseCreate(BaseModel):
    property_id: int
    amount: float = Field(..., gt=0)
    currency: Optional[str] = "USDT"
    wallet_address: str
    tx_hash: Optional[str] = None

class CryptoPurchaseConfirm(BaseModel):
    tx_hash: str = Field(..., min_length=10)

class ChatMessageCreate(BaseModel):
    message: str = Field(..., min_length=1, max_length=1000)
    property_id: Optional[int] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str
class PropertyImageUpload(BaseModel):
    image_url: str

class PropertyCreate(BaseModel):
    title: str = Field(..., min_length=5)
    description: Optional[str] = None
    property_type: str = Field(..., pattern="^(apartment|house|villa|commercial|land)$")
    deal_type: str = Field(..., pattern="^(sale|rent)$")
    price: float = Field(..., gt=0)
    city: str = Field(..., min_length=2)
    district: str = Field(..., min_length=2)
    address: Optional[str] = None
    rooms: Optional[str] = None
    area: Optional[float] = Field(None, gt=0)
    floor: Optional[int] = Field(None, ge=0)
    total_floors: Optional[int] = Field(None, gt=0)
    year_built: Optional[int] = Field(None, ge=1800, le=datetime.now().year)
    latitude: Optional[float] = Field(None, ge=-90, le=90)
    longitude: Optional[float] = Field(None, ge=-180, le=180)
    images: Optional[List[str]] = []
    amenities: Optional[List[str]] = []

# НОВАЯ МОДЕЛЬ ДЛЯ JSON ЗАПРОСОВ
class PropertyCreateJSON(BaseModel):
    title: str
    description: Optional[str] = ""
    property_type: str
    deal_type: str
    price: float
    city: str
    district: str
    address: Optional[str] = None
    rooms: Optional[str] = None
    area: Optional[float] = None
    floor: Optional[int] = None
    total_floors: Optional[int] = None
    year_built: Optional[int] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    images: Optional[List[str]] = []
    amenities: Optional[List[str]] = []

class PropertyAdminUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=5)
    description: Optional[str] = None
    price: Optional[float] = Field(None, gt=0)
    city: Optional[str] = Field(None, min_length=2)
    district: Optional[str] = None
    status: Optional[str] = Field(None, pattern="^(available|sold|pending)$")

class PropertyStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(available|sold|pending)$")

class CryptoWalletConfig(BaseModel):
    wallet_address: str = Field(..., min_length=10)
    currency: Optional[str] = Field("USDT", pattern="^(USDT|BTC|ETH|BNB|TRX)$")
    network: Optional[str] = Field(None)
    
    @validator('wallet_address')
    def validate_wallet_address(cls, v):
        if not v:
            raise ValueError('Адрес кошелька не может быть пустым')
        if len(v) < 10:
            raise ValueError('Адрес кошелька слишком короткий')
        return v

class OrderCreate(BaseModel):
    property_id: Optional[int] = None
    amount: float = Field(..., gt=0)
    currency: Optional[str] = "USD"
    note: Optional[str] = None

class InvoiceConfirm(BaseModel):
    tx_hash: str = Field(..., min_length=10)

class UserRoleUpdate(BaseModel):
    role: str = Field(..., pattern="^(user|admin|agent)$")

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(auth: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(auth.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Недействительный токен")
        
        conn = sqlite3.connect('turkey_realty.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, email, name, phone, role, avatar, description, is_active 
            FROM users WHERE id = ?
        ''', (user_id,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            raise HTTPException(status_code=401, detail="Пользователь не найден")
        
        if not row[7]:
            raise HTTPException(status_code=403, detail="Аккаунт деактивирован")
        
        return {
            "id": row[0],
            "email": row[1],
            "name": row[2],
            "phone": row[3],
            "role": row[4] or "user",
            "avatar": row[5],
            "description": row[6]
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Срок действия токена истек")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Недействительный токен")
    except Exception as e:
        print(f"Auth error: {e}")
        raise HTTPException(status_code=401, detail="Не удалось проверить учетные данные")

async def get_current_admin(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Требуются права администратора")
    return current_user

def log_admin(admin_id: int, action: str, entity_type: str = None, entity_id: int = None, details: str = ""):
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO admin_audit_logs (admin_id, action, entity_type, entity_id, details) VALUES (?, ?, ?, ?, ?)",
        (admin_id, action, entity_type, entity_id, details)
    )
    conn.commit()
    conn.close()

def log_payment(order_id: Optional[int], invoice_id: Optional[int], action: str, details: str = "", request: Request = None):
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    ip = request.client.host if request else None
    cursor.execute(
        "INSERT INTO payment_logs (order_id, invoice_id, action, details, ip_address) VALUES (?, ?, ?, ?, ?)",
        (order_id, invoice_id, action, details, ip)
    )
    conn.commit()
    conn.close()

# --- PUBLIC ENDPOINTS ---

# --- CRYPTO PURCHASE ENDPOINTS ---

@app.post("/api/crypto/purchase")
async def create_crypto_purchase(
    purchase: CryptoPurchaseCreate,
    current_user: dict = Depends(get_current_user)
):
    """Создание заявки на крипто-покупку"""
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, title, price, status FROM properties WHERE id = ?", (purchase.property_id,))
    property_data = cursor.fetchone()
    if not property_data:
        conn.close()
        raise HTTPException(status_code=404, detail="Объект не найден")
    
    if property_data[3] != 'available':
        conn.close()
        raise HTTPException(status_code=400, detail="Объект недоступен для покупки")
    
    cursor.execute('''
        INSERT INTO crypto_purchases (property_id, user_id, amount, currency, wallet_address, tx_hash, status)
        VALUES (?, ?, ?, ?, ?, ?, 'pending')
    ''', (purchase.property_id, current_user["id"], purchase.amount, 
          purchase.currency, purchase.wallet_address, purchase.tx_hash))
    
    purchase_id = cursor.lastrowid
    
    cursor.execute('''
        INSERT OR IGNORE INTO property_chats (property_id, user_id, seller_id)
        VALUES (?, ?, 1)
    ''', (purchase.property_id, current_user["id"]))
    
    chat_id = cursor.lastrowid or cursor.execute(
        "SELECT id FROM property_chats WHERE property_id = ? AND user_id = ?",
        (purchase.property_id, current_user["id"])
    ).fetchone()[0]
    
    cursor.execute('''
        INSERT INTO chat_messages (chat_id, sender_id, message)
        VALUES (?, ?, ?)
    ''', (chat_id, current_user["id"], 
          f"Пользователь начал процесс покупки объекта через криптовалюту. Сумма: {purchase.amount} {purchase.currency}"))
    
    cursor.execute('''
        INSERT INTO admin_notifications (admin_id, type, title, message, entity_type, entity_id)
        VALUES (1, 'crypto_purchase', 'Новая крипто-покупка!', 
                'Пользователь {} начал покупку объекта "{}" за {} {}', 'crypto_purchase', ?)
    ''', (current_user["name"], property_data[1], purchase.amount, purchase.currency, purchase_id))
    
    conn.commit()
    
    cursor.execute("SELECT wallet_address, currency, network FROM crypto_wallet_config WHERE id = 1")
    wallet = cursor.fetchone()
    
    conn.close()
    
    qr_code_base64 = None
    if wallet:
        try:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(wallet[0])
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            buffer.seek(0)
            qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
        except Exception as e:
            print(f"QR code generation error: {e}")
    
    message = f"💰 <b>НОВАЯ КРИПТО-ПОКУПКА!</b>\n"
    message += f"👤 Пользователь: {current_user['name']}\n"
    message += f"🏠 Объект: {property_data[1]}\n"
    message += f"💵 Сумма: {purchase.amount} {purchase.currency}\n"
    message += f"🔗 Адрес: {purchase.wallet_address}\n"
    message += f"🆔 ID покупки: {purchase_id}"
    send_telegram_notification(message)
    
    return {
        "success": True,
        "purchase_id": purchase_id,
        "crypto_address": wallet[0] if wallet else "",
        "currency": wallet[1] if wallet else "USDT",
        "network": wallet[2] if wallet else "ERC-20",
        "qr_code": qr_code_base64,
        "amount": purchase.amount,
        "message": "Заявка создана. Отсканируйте QR код для оплаты."
    }

@app.post("/api/crypto/purchase/{purchase_id}/confirm")
async def confirm_crypto_purchase(
    purchase_id: int,
    confirm: CryptoPurchaseConfirm,
    admin: dict = Depends(get_current_admin)
):
    """Подтверждение крипто-покупки админом"""
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT cp.*, p.title, u.name, u.email 
        FROM crypto_purchases cp
        JOIN properties p ON p.id = cp.property_id
        JOIN users u ON u.id = cp.user_id
        WHERE cp.id = ? AND cp.status = 'pending'
    ''', (purchase_id,))
    
    purchase = cursor.fetchone()
    if not purchase:
        conn.close()
        raise HTTPException(status_code=404, detail="Покупка не найдена или уже обработана")
    
    cursor.execute('''
        UPDATE crypto_purchases 
        SET status = 'confirmed', tx_hash = ?, confirmed_at = CURRENT_TIMESTAMP 
        WHERE id = ?
    ''', (confirm.tx_hash, purchase_id))
    
    cursor.execute("UPDATE properties SET status = 'sold' WHERE id = ?", (purchase[1],))
    
    cursor.execute('''
        INSERT INTO orders (user_id, property_id, amount, currency, status)
        VALUES (?, ?, ?, ?, 'paid')
    ''', (purchase[2], purchase[1], purchase[3], purchase[4]))
    
    order_id = cursor.lastrowid
    
    cursor.execute('''
        SELECT id FROM property_chats 
        WHERE property_id = ? AND user_id = ?
    ''', (purchase[1], purchase[2]))
    
    chat_id_row = cursor.fetchone()
    if chat_id_row:
        cursor.execute('''
            INSERT INTO chat_messages (chat_id, sender_id, message)
            VALUES (?, ?, ?)
        ''', (chat_id_row[0], admin["id"], 
              f"✅ Покупка подтверждена! Объект переведен в статус 'Продан'. TX Hash: {confirm.tx_hash}"))
    
    conn.commit()
    conn.close()
    
    log_admin(admin["id"], "crypto_purchase_confirmed", "crypto_purchase", purchase_id)
    
    message = f"✅ <b>КРИПТО-ПОКУПКА ПОДТВЕРЖДЕНА!</b>\n"
    message += f"👤 Пользователь: {purchase[14]}\n"
    message += f"🏠 Объект: {purchase[13]}\n"
    message += f"💵 Сумма: {purchase[3]} {purchase[4]}\n"
    message += f"🔗 TX Hash: {confirm.tx_hash}\n"
    message += f"👨‍💼 Админ: {admin['name']}"
    send_telegram_notification(message)
    
    return {"message": "Покупка подтверждена успешно"}

@app.get("/api/crypto/purchases")
async def get_user_crypto_purchases(current_user: dict = Depends(get_current_user)):
    """Получить все крипто-покупки пользователя"""
    conn = sqlite3.connect('turkey_realty.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT cp.*, p.title as property_title, p.price as property_price
        FROM crypto_purchases cp
        JOIN properties p ON p.id = cp.property_id
        WHERE cp.user_id = ?
        ORDER BY cp.created_at DESC
    ''', (current_user["id"],))
    
    purchases = cursor.fetchall()
    conn.close()
    
    return [dict(purchase) for purchase in purchases]

@app.get("/api/crypto/purchase/{purchase_id}")
async def get_crypto_purchase_details(
    purchase_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Получить детали крипто-покупки и генерировать QR код"""
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT cp.*, p.title as property_title
        FROM crypto_purchases cp
        JOIN properties p ON p.id = cp.property_id
        WHERE cp.id = ? AND cp.user_id = ?
    ''', (purchase_id, current_user["id"]))
    
    purchase = cursor.fetchone()
    
    if not purchase:
        conn.close()
        raise HTTPException(status_code=404, detail="Покупка не найдена")
    
    cursor.execute("SELECT wallet_address, currency, network FROM crypto_wallet_config WHERE id = 1")
    wallet = cursor.fetchone()
    conn.close()
    
    qr_code_base64 = None
    if wallet:
        try:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(wallet[0])
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            buffer.seek(0)
            qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
        except Exception as e:
            print(f"QR code generation error: {e}")
    
    return {
        "id": purchase[0],
        "property_id": purchase[1],
        "user_id": purchase[2],
        "amount": purchase[3],
        "currency": purchase[4],
        "wallet_address": purchase[5],
        "tx_hash": purchase[6],
        "status": purchase[7],
        "created_at": purchase[8],
        "confirmed_at": purchase[9],
        "property_title": purchase[10],
        "crypto_address": wallet[0] if wallet else "",
        "network": wallet[2] if wallet else "ERC-20",
        "qr_code": qr_code_base64
    }

@app.get("/api/admin/crypto/purchases")
async def admin_get_all_crypto_purchases(admin: dict = Depends(get_current_admin)):
    """Получить все крипто-покупки (для админа)"""
    conn = sqlite3.connect('turkey_realty.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT cp.*, p.title as property_title, u.name as user_name, u.email as user_email
        FROM crypto_purchases cp
        JOIN properties p ON p.id = cp.property_id
        JOIN users u ON u.id = cp.user_id
        ORDER BY cp.created_at DESC
    ''')
    
    purchases = cursor.fetchall()
    conn.close()
    
    return [dict(purchase) for purchase in purchases]

# --- CHAT ENDPOINTS ---

@app.get("/api/chats")
async def get_user_chats(current_user: dict = Depends(get_current_user)):
    """Получить все чаты пользователя"""
    conn = sqlite3.connect('turkey_realty.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT pc.*, p.title as property_title, p.price, 
               u.name as seller_name,
               (SELECT message FROM chat_messages WHERE chat_id = pc.id ORDER BY created_at DESC LIMIT 1) as last_message,
               (SELECT COUNT(*) FROM chat_messages WHERE chat_id = pc.id AND is_read = 0 AND sender_id != ?) as unread_count
        FROM property_chats pc
        JOIN properties p ON p.id = pc.property_id
        LEFT JOIN users u ON u.id = pc.seller_id
        WHERE pc.user_id = ? OR pc.seller_id = ?
        ORDER BY pc.last_message_at DESC
    ''', (current_user["id"], current_user["id"], current_user["id"]))
    
    chats = cursor.fetchall()
    conn.close()
    
    return [dict(chat) for chat in chats]

@app.get("/api/chats/{property_id}")
async def get_or_create_chat(property_id: int, current_user: dict = Depends(get_current_user)):
    """Получить или создать чат для объекта"""
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, title FROM properties WHERE id = ?", (property_id,))
    property_data = cursor.fetchone()
    if not property_data:
        conn.close()
        raise HTTPException(status_code=404, detail="Объект не найден")
    
    cursor.execute('''
        SELECT id FROM property_chats 
        WHERE property_id = ? AND user_id = ?
    ''', (property_id, current_user["id"]))
    
    chat = cursor.fetchone()
    
    if not chat:
        cursor.execute('''
            INSERT INTO property_chats (property_id, user_id, seller_id)
            VALUES (?, ?, 1)
        ''', (property_id, current_user["id"]))
        
        chat_id = cursor.lastrowid
        
        cursor.execute('''
            INSERT INTO chat_messages (chat_id, sender_id, message)
            VALUES (?, ?, ?)
        ''', (chat_id, 1, f"Здравствуйте! Я помогу вам с покупкой объекта '{property_data[1]}'"))
        
        cursor.execute('''
            INSERT INTO admin_notifications (admin_id, type, title, message, entity_type, entity_id)
            VALUES (1, 'new_chat', 'Новый чат с клиентом!', 
                    'Пользователь {} начал диалог по объекту "{}"', 'chat', ?)
        ''', (current_user["name"], property_data[1], chat_id))
        
        conn.commit()
    else:
        chat_id = chat[0]
    
    conn.close()
    
    return {"chat_id": chat_id, "property_title": property_data[1]}

@app.get("/api/chats/{chat_id}/messages")
async def get_chat_messages(chat_id: int, current_user: dict = Depends(get_current_user)):
    """Получить сообщения чата"""
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id FROM property_chats 
        WHERE id = ? AND (user_id = ? OR seller_id = ?)
    ''', (chat_id, current_user["id"], current_user["id"]))
    
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=403, detail="Нет доступа к этому чату")
    
    cursor.execute('''
        UPDATE chat_messages 
        SET is_read = 1 
        WHERE chat_id = ? AND sender_id != ? AND is_read = 0
    ''', (chat_id, current_user["id"]))
    
    cursor.execute('''
        SELECT cm.*, u.name as sender_name, u.role as sender_role
        FROM chat_messages cm
        JOIN users u ON u.id = cm.sender_id
        WHERE cm.chat_id = ?
        ORDER BY cm.created_at ASC
    ''', (chat_id,))
    
    messages = cursor.fetchall()
    
    conn.commit()
    conn.close()
    
    return [
        {
            "id": msg[0],
            "chat_id": msg[1],
            "sender_id": msg[2],
            "sender_name": msg[6],
            "sender_role": msg[7],
            "message": msg[3],
            "is_read": bool(msg[4]),
            "created_at": msg[5]
        }
        for msg in messages
    ]

@app.post("/api/chats/{chat_id}/messages")
async def send_chat_message(
    chat_id: int,
    message: ChatMessageCreate,
    current_user: dict = Depends(get_current_user)
):
    """Отправить сообщение в чат"""
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, property_id, user_id, seller_id FROM property_chats 
        WHERE id = ? AND (user_id = ? OR seller_id = ?)
    ''', (chat_id, current_user["id"], current_user["id"]))
    
    chat = cursor.fetchone()
    if not chat:
        conn.close()
        raise HTTPException(status_code=403, detail="Нет доступа к этому чату")
    
    cursor.execute('''
        INSERT INTO chat_messages (chat_id, sender_id, message)
        VALUES (?, ?, ?)
    ''', (chat_id, current_user["id"], message.message))
    
    cursor.execute('''
        UPDATE property_chats 
        SET last_message_at = CURRENT_TIMESTAMP 
        WHERE id = ?
    ''', (chat_id,))
    
    recipient_id = chat[2] if current_user["id"] == chat[3] else chat[3]
    
    if recipient_id == 1:
        cursor.execute('''
            INSERT INTO admin_notifications (admin_id, type, title, message, entity_type, entity_id)
            VALUES (1, 'chat_message', 'Новое сообщение в чате', 
                    'Пользователь {} отправил сообщение', 'chat', ?)
        ''', (current_user["name"], chat_id))
    
    conn.commit()
    conn.close()
    
    return {"success": True, "message": "Сообщение отправлено"}

# --- NOTIFICATIONS ENDPOINTS ---

@app.get("/api/notifications")
async def get_notifications(admin: dict = Depends(get_current_admin)):
    """Получить уведомления админа"""
    conn = sqlite3.connect('turkey_realty.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT * FROM admin_notifications 
        WHERE admin_id = ? 
        ORDER BY created_at DESC 
        LIMIT 50
    ''', (admin["id"],))
    
    notifications = cursor.fetchall()
    conn.close()
    
    return [dict(notif) for notif in notifications]

@app.post("/api/notifications/{notification_id}/read")
async def mark_notification_read(notification_id: int, admin: dict = Depends(get_current_admin)):
    """Пометить уведомление как прочитанное"""
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE admin_notifications 
        SET is_read = 1 
        WHERE id = ? AND admin_id = ?
    ''', (notification_id, admin["id"]))
    
    conn.commit()
    conn.close()
    
    return {"success": True}

@app.post("/api/admin/orders")
async def create_order(
    order: OrderCreate,
    current_user: dict = Depends(get_current_user)
):
    """Создание заказа"""
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO orders (user_id, property_id, amount, currency, status, notes)
            VALUES (?, ?, ?, ?, 'pending', ?)
        ''', (current_user["id"], order.property_id, order.amount, order.currency, order.note))
        
        order_id = cursor.lastrowid
        
        cursor.execute('''
            INSERT INTO admin_notifications (admin_id, type, title, message, entity_type, entity_id)
            VALUES (1, 'new_order', 'Новый заказ!', 
                    'Пользователь {} создал новый заказ на сумму {} {}', 'order', ?)
        ''', (current_user["name"], order.amount, order.currency, order_id))
        
        conn.commit()
        conn.close()
        
        message = f"🛒 <b>НОВЫЙ ЗАКАЗ!</b>\n"
        message += f"👤 Пользователь: {current_user['name']}\n"
        message += f"💰 Сумма: {order.amount} {order.currency}\n"
        if order.property_id:
            cursor.execute("SELECT title FROM properties WHERE id = ?", (order.property_id,))
            prop = cursor.fetchone()
            if prop:
                message += f"🏠 Объект: {prop[0]}\n"
        message += f"🆔 ID заказа: {order_id}"
        send_telegram_notification(message)
        
        return {
            "success": True,
            "order_id": order_id,
            "message": "Заказ создан успешно"
        }
        
    except Exception as e:
        conn.rollback()
        conn.close()
        print(f"Error creating order: {e}")
        raise HTTPException(status_code=500, detail="Ошибка создания заказа")

@app.post("/api/register")
async def register(user: UserRegister):
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = ?", (user.email,))
    existing_user = cursor.fetchone()
    
    if existing_user:
        conn.close()
        raise HTTPException(status_code=400, detail="Email уже зарегистрирован")
    
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    try:
        cursor.execute(
            'INSERT INTO users (email, password, name, phone) VALUES (?, ?, ?, ?)',
            (user.email, hashed_password, user.name, user.phone)
        )
        user_id = cursor.lastrowid
        conn.commit()
        
        token = create_access_token({"user_id": user_id})
        
        message = f"👤 <b>Новый пользователь на BROKEROK!</b>\n"
        message += f"Имя: {user.name}\n"
        message += f"Email: {user.email}\n"
        message += f"Телефон: {user.phone or 'Не указан'}\n"
        message += f"ID: {user_id}"
        send_telegram_notification(message)
        
        return {
            "success": True,
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "id": user_id,
                "name": user.name,
                "email": user.email,
                "role": "user"
            }
        }
    except Exception as e:
        print(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail="Ошибка регистрации")
    finally:
        conn.close()

@app.post("/api/login")
async def login(user: UserLogin):
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, password, name, email, role, is_active 
        FROM users WHERE email = ?
    ''', (user.email,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=401, detail="Неверный email или пароль")
    
    if not row[5]:
        raise HTTPException(status_code=403, detail="Аккаунт деактивирован")
    
    if bcrypt.checkpw(user.password.encode('utf-8'), row[1].encode('utf-8')):
        conn = sqlite3.connect('turkey_realty.db')
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
            (row[0],)
        )
        conn.commit()
        conn.close()
        
        token = create_access_token({"user_id": row[0]})
        user_data = {
            "id": row[0],
            "name": row[2],
            "email": row[3],
            "role": row[4] or "user"
        }
        
        return {
            "success": True,
            "access_token": token,
            "token_type": "bearer",
            "user": user_data
        }
    else:
        raise HTTPException(status_code=401, detail="Неверный email или пароль")

@app.get("/api/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return current_user

# ВСЕ КОД ОСТАВЛЯЕМ КАК ЕСТЬ ДО ЭНДПОИНТА check-session

# УДАЛИТЕ этот эндпоинт (если он у вас есть):
# @app.get("/api/check-session")
# async def check_session(request: Request):
#     ...

# И оставьте только этот (правильный) эндпоинт:
@app.get("/api/check-session")
async def check_session(auth: HTTPAuthorizationCredentials = Depends(security)):
    """Проверка сессии пользователя"""
    try:
        payload = jwt.decode(auth.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        if user_id is None:
            return {"valid": False}
        
        conn = sqlite3.connect('turkey_realty.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, email, name, phone, role, avatar, description, is_active 
            FROM users WHERE id = ?
        ''', (user_id,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return {"valid": False}
        
        if not row[7]:
            return {"valid": False, "message": "Аккаунт деактивирован"}
        
        return {
            "valid": True,
            "user": {
                "id": row[0],
                "email": row[1],
                "name": row[2],
                "phone": row[3],
                "role": row[4] or "user",
                "avatar": row[5],
                "description": row[6]
            }
        }
    except jwt.ExpiredSignatureError:
        return {"valid": False, "message": "Срок действия токена истек"}
    except jwt.InvalidTokenError:
        return {"valid": False, "message": "Недействительный токен"}
    except Exception as e:
        print(f"Session check error: {e}")
        return {"valid": False, "message": "Ошибка проверки сессии"}

# Добавьте публичный эндпоинт для крипто-кошелька:
@app.get("/api/crypto/wallet")
async def get_crypto_wallet_public(current_user: dict = Depends(get_current_user)):
    """Получить настройки крипто-кошелька (публичный доступ)"""
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    cursor.execute("SELECT wallet_address, currency, network, updated_at FROM crypto_wallet_config WHERE id = 1")
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return {
            "wallet_address": row[0] or "",
            "currency": row[1] or "USDT",
            "network": row[2] or "",
            "updated_at": row[3]
        }
    
    return {"wallet_address": "", "currency": "USDT", "network": "", "updated_at": None}

# Также нужно добавить эндпоинт для создания чата через POST:
@app.post("/api/chats")
async def create_chat_message(
    message: ChatMessageCreate,
    current_user: dict = Depends(get_current_user)
):
    """Создать новое сообщение в чате или начать чат"""
    try:
        conn = sqlite3.connect('turkey_realty.db')
        cursor = conn.cursor()
        
        if not message.property_id:
            raise HTTPException(status_code=400, detail="Не указан ID объекта")
        
        # Проверяем существование объекта
        cursor.execute("SELECT id, title FROM properties WHERE id = ?", (message.property_id,))
        property_data = cursor.fetchone()
        if not property_data:
            conn.close()
            raise HTTPException(status_code=404, detail="Объект не найден")
        
        # Проверяем существующий чат или создаем новый
        cursor.execute('''
            SELECT id FROM property_chats 
            WHERE property_id = ? AND user_id = ?
        ''', (message.property_id, current_user["id"]))
        
        chat = cursor.fetchone()
        
        if not chat:
            # Создаем новый чат
            cursor.execute('''
                INSERT INTO property_chats (property_id, user_id, seller_id)
                VALUES (?, ?, 1)
            ''', (message.property_id, current_user["id"]))
            
            chat_id = cursor.lastrowid
            
            # Добавляем приветственное сообщение от менеджера
            cursor.execute('''
                INSERT INTO chat_messages (chat_id, sender_id, message)
                VALUES (?, ?, ?)
            ''', (chat_id, 1, f"Здравствуйте! Я помогу вам с покупкой объекта '{property_data[1]}'"))
            
            # Добавляем сообщение пользователя
            cursor.execute('''
                INSERT INTO chat_messages (chat_id, sender_id, message)
                VALUES (?, ?, ?)
            ''', (chat_id, current_user["id"], message.message))
            
            # Добавляем уведомление админу
            cursor.execute('''
                INSERT INTO admin_notifications (admin_id, type, title, message, entity_type, entity_id)
                VALUES (1, 'new_chat', 'Новый чат с клиентом!', 
                        'Пользователь {} начал диалог по объекту "{}"', 'chat', ?)
            ''', (current_user["name"], property_data[1], chat_id))
            
        else:
            chat_id = chat[0]
            # Просто добавляем сообщение в существующий чат
            cursor.execute('''
                INSERT INTO chat_messages (chat_id, sender_id, message)
                VALUES (?, ?, ?)
            ''', (chat_id, current_user["id"], message.message))
        
        conn.commit()
        conn.close()
        
        return {"success": True, "message": "Сообщение отправлено", "chat_id": chat_id}
        
    except Exception as e:
        print(f"Error creating chat message: {e}")
        raise HTTPException(status_code=500, detail="Ошибка отправки сообщения")

# ОСТАЛЬНОЙ КОД ОСТАВЛЯЕМ БЕЗ ИЗМЕНЕНИЙ

@app.get("/api/cities")
async def get_cities():
    return [
        {"name": "Стамбул", "value": "istanbul"},
        {"name": "Анталья", "value": "antalya"},
        {"name": "Алания", "value": "alanya"},
        {"name": "Бодрум", "value": "bodrum"},
        {"name": "Фетхие", "value": "fethiye"},
        {"name": "Измир", "value": "izmir"},
        {"name": "Анкара", "value": "ankara"},
        {"name": "Кемер", "value": "kemer"},
        {"name": "Сиде", "value": "side"},
        {"name": "Белек", "value": "belek"}
    ]

@app.post("/api/upload")
async def upload_file(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    """Загрузка файла на сервер"""
    try:
        file.file.seek(0, 2)
        file_size = file.file.tell()
        file.file.seek(0)
        
        if file_size > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=400,
                detail=f"Файл слишком большой. Максимальный размер: {MAX_FILE_SIZE // 1024 // 1024}MB"
            )
        
        if file.content_type not in ALLOWED_IMAGE_TYPES:
            raise HTTPException(
                status_code=400,
                detail=f"Недопустимый тип файла. Разрешены: {', '.join([t.split('/')[1] for t in ALLOWED_IMAGE_TYPES])}"
            )
        
        file_extension = file.filename.split('.')[-1] if '.' in file.filename else 'jpg'
        filename = f"{uuid.uuid4().hex}.{file_extension}"
        file_path = UPLOAD_DIR / filename
        
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        file_url = f"/uploads/{filename}"
        
        return {
            "success": True,
            "filename": filename,
            "url": file_url,
            "message": "Файл успешно загружен"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Ошибка загрузки файла: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка загрузки файла: {str(e)}")

@app.get("/uploads/{filename}")
async def get_uploaded_file(filename: str):
    """Получение загруженного файла"""
    file_path = UPLOAD_DIR / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Файл не найден")
    return FileResponse(file_path)

@app.get("/api/properties/{property_id}")
async def get_property(property_id: int, request: Request):
    conn = sqlite3.connect('turkey_realty.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM properties WHERE id = ?", (property_id,))
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Объект не найден")
    
    p = dict(row)
    p["images"] = json.loads(p["images"]) if p["images"] else []
    p["amenities"] = json.loads(p["amenities"]) if p["amenities"] else []
    p["status"] = p.get("status") or "available"
    
    cursor.execute(
        "UPDATE properties SET views = views + 1 WHERE id = ?",
        (property_id,)
    )
    
    ip_address = request.client.host
    cursor.execute(
        "INSERT INTO property_views (property_id, ip_address) VALUES (?, ?)",
        (property_id, ip_address)
    )
    
    conn.commit()
    conn.close()
    
    return p

@app.get("/api/properties")
async def get_properties(
    city: Optional[str] = None,
    property_type: Optional[str] = None,
    deal_type: Optional[str] = None,
    max_price: Optional[float] = None,
    min_price: Optional[float] = None,
    status: Optional[str] = None
):
    conn = sqlite3.connect('turkey_realty.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    query = "SELECT * FROM properties WHERE 1=1"
    params = []
    
    if status:
        query += " AND status = ?"
        params.append(status)
    
    if city:
        query += " AND city = ?"
        params.append(city)
    
    if property_type:
        query += " AND property_type = ?"
        params.append(property_type)
    
    if deal_type:
        query += " AND deal_type = ?"
        params.append(deal_type)
    
    if max_price:
        query += " AND price <= ?"
        params.append(max_price)
    
    if min_price:
        query += " AND price >= ?"
        params.append(min_price)
    
    query += " ORDER BY created_at DESC"
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    
    properties = []
    for row in rows:
        p = dict(row)
        p["images"] = json.loads(p["images"]) if p["images"] else []
        p["amenities"] = json.loads(p["amenities"]) if p["amenities"] else []
        p["status"] = p.get("status") or "available"
        properties.append(p)
    
    return {"properties": properties}

# --- ADMIN ENDPOINTS ---

@app.get("/api/admin/properties/{property_id}")
async def admin_get_property(property_id: int, admin: dict = Depends(get_current_admin)):
    """Получение конкретного объекта для админа"""
    conn = sqlite3.connect('turkey_realty.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM properties WHERE id = ?", (property_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=404, detail="Объект не найден")
    
    p = dict(row)
    p["images"] = json.loads(p["images"]) if p.get("images") else []
    p["amenities"] = json.loads(p["amenities"]) if p.get("amenities") else []
    p["status"] = p.get("status") or "available"
    
    return p

@app.get("/api/admin/stats")
async def admin_stats(admin: dict = Depends(get_current_admin)):
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM users")
    users_count = cursor.fetchone()[0] or 0
    
    cursor.execute("SELECT COUNT(*) FROM users WHERE DATE(created_at) = DATE('now')")
    users_today = cursor.fetchone()[0] or 0
    
    cursor.execute("SELECT COUNT(*) FROM users WHERE DATE(last_login) = DATE('now')")
    active_today = cursor.fetchone()[0] or 0
    
    cursor.execute("SELECT COUNT(*) FROM properties")
    total_properties = cursor.fetchone()[0] or 0
    
    cursor.execute("SELECT COUNT(*) FROM properties WHERE status = 'available'")
    available_count = cursor.fetchone()[0] or 0
    
    cursor.execute("SELECT COUNT(*) FROM properties WHERE status = 'sold'")
    sold_count = cursor.fetchone()[0] or 0
    
    cursor.execute("SELECT COUNT(*) FROM properties WHERE status = 'pending'")
    pending_count = cursor.fetchone()[0] or 0
    
    cursor.execute("SELECT SUM(price) FROM properties WHERE status = 'sold'")
    total_sales_result = cursor.fetchone()[0]
    total_sales = float(total_sales_result) if total_sales_result else 0.0
    
    cursor.execute("SELECT COUNT(*) FROM orders")
    total_orders = cursor.fetchone()[0] or 0
    
    cursor.execute("SELECT COUNT(*) FROM orders WHERE status = 'paid'")
    paid_orders = cursor.fetchone()[0] or 0
    
    cursor.execute("SELECT COUNT(*) FROM orders WHERE status = 'pending'")
    pending_orders = cursor.fetchone()[0] or 0
    
    cursor.execute("SELECT SUM(amount) FROM orders WHERE status = 'paid'")
    revenue_result = cursor.fetchone()[0]
    revenue = float(revenue_result) if revenue_result else 0.0
    
    cursor.execute("SELECT COUNT(*) FROM page_views WHERE DATE(created_at) = DATE('now')")
    views_today = cursor.fetchone()[0] or 0
    
    cursor.execute("SELECT COUNT(*) FROM page_views")
    views_total = cursor.fetchone()[0] or 0
    
    cursor.execute("SELECT city, COUNT(*) as count FROM properties GROUP BY city ORDER BY count DESC LIMIT 10")
    cities_data = cursor.fetchall()
    
    cursor.execute('''
        SELECT l.id, l.admin_id, l.action, l.entity_type, l.entity_id, 
               l.details, l.created_at, u.name as admin_name 
        FROM admin_audit_logs l 
        LEFT JOIN users u ON u.id = l.admin_id 
        ORDER BY l.created_at DESC LIMIT 10
    ''')
    recent_activity = cursor.fetchall()
    
    week_stats = []
    for i in range(6, -1, -1):
        date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        cursor.execute("SELECT COUNT(*) FROM properties WHERE DATE(created_at) = ?", (date,))
        props = cursor.fetchone()[0] or 0
        
        cursor.execute("SELECT COUNT(*) FROM users WHERE DATE(created_at) = ?", (date,))
        users = cursor.fetchone()[0] or 0
        
        cursor.execute("SELECT SUM(amount) FROM orders WHERE status = 'paid' AND DATE(created_at) = ?", (date,))
        daily_revenue_result = cursor.fetchone()[0]
        daily_revenue = float(daily_revenue_result) if daily_revenue_result else 0.0
        
        week_stats.append({
            "date": date,
            "properties": props,
            "users": users,
            "revenue": daily_revenue
        })
    
    conn.close()
    
    return {
        "users": {
            "total": int(users_count),
            "today": int(users_today),
            "active_today": int(active_today)
        },
        "properties": {
            "total": int(total_properties),
            "available": int(available_count),
            "sold": int(sold_count),
            "pending": int(pending_count),
            "total_sales": float(total_sales)
        },
        "orders": {
            "total": int(total_orders),
            "paid": int(paid_orders),
            "pending": int(pending_orders),
            "revenue": float(revenue)
        },
        "views": {
            "today": int(views_today),
            "total": int(views_total)
        },
        "cities": [{"city": row[0], "count": row[1]} for row in cities_data],
        "recent_activity": [
            {
                "id": row[0],
                "admin_id": row[1],
                "action": row[2],
                "entity_type": row[3],
                "entity_id": row[4],
                "details": row[5],
                "created_at": row[6],
                "admin_name": row[7]
            } for row in recent_activity
        ],
        "week_stats": week_stats
    }

@app.get("/api/admin/map-data")
async def get_map_data(admin: dict = Depends(get_current_admin)):
    """Получить данные для карты"""
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, title, price, city, district, latitude, longitude, status 
        FROM properties 
        WHERE latitude IS NOT NULL AND longitude IS NOT NULL
        ORDER BY created_at DESC
    """)
    properties = cursor.fetchall()
    conn.close()
    
    city_coords = {
        'istanbul': (41.0082, 28.9784),
        'antalya': (36.8969, 30.7133),
        'alanya': (36.5438, 31.9998),
        'bodrum': (37.0344, 27.4305),
        'fethiye': (36.6217, 29.1164),
        'izmir': (38.4237, 27.1428),
        'ankara': (39.9334, 32.8597),
        'kemer': (36.6000, 30.5667),
        'side': (36.7667, 31.3889),
        'belek': (36.8667, 31.0500)
    }
    
    result = []
    for p in properties:
        lat, lng = p[5], p[6]
        if not lat or not lng:
            city_lower = p[3].lower()
            if city_lower in city_coords:
                lat, lng = city_coords[city_lower]
            else:
                lat, lng = 39.9334, 32.8597
        
        result.append({
            "id": p[0],
            "title": p[1],
            "price": p[2],
            "city": p[3],
            "district": p[4],
            "lat": float(lat),
            "lng": float(lng),
            "status": p[7] or "available"
        })
    
    return result

@app.get("/api/admin/properties")
async def admin_list_properties(
    admin: dict = Depends(get_current_admin),
    status: Optional[str] = None,
    city: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    try:
        conn = sqlite3.connect('turkey_realty.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = "SELECT * FROM properties WHERE 1=1"
        params = []
        
        if status:
            query += " AND status = ?"
            params.append(status)
        
        if city:
            query += " AND city = ?"
            params.append(city)
        
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        count_query = "SELECT COUNT(*) FROM properties WHERE 1=1"
        count_params = []
        
        if status:
            count_query += " AND status = ?"
            count_params.append(status)
        
        if city:
            count_query += " AND city = ?"
            count_params.append(city)
        
        cursor.execute(count_query, count_params)
        total = cursor.fetchone()[0] or 0
        
        conn.close()
        
        properties = []
        for row in rows:
            p = dict(row)
            p["images"] = json.loads(p["images"]) if p.get("images") else []
            p["amenities"] = json.loads(p["amenities"]) if p.get("amenities") else []
            p["status"] = p.get("status") or "available"
            properties.append(p)
        
        return {
            "properties": properties,
            "total": total,
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        print(f"Error in admin_list_properties: {e}")
        return {"properties": [], "total": 0}

# НОВЫЙ ЭНДПОИНТ ДЛЯ JSON (для админ-панели)
# Дополнительно к существующим моделям добавьте:
class PropertyImageUpload(BaseModel):
    image_url: str

# В методе admin_create_property_json измените обработку изображений:
@app.post("/api/admin/properties/json")
async def admin_create_property_json(
    property_data: PropertyCreateJSON,
    admin: dict = Depends(get_current_admin)
):
    """Создание объекта через JSON (для админ-панели) с загрузкой изображений"""
    try:
        print(f"Создание объекта от админа {admin['name']}: {property_data.title}")
        
        conn = sqlite3.connect('turkey_realty.db')
        cursor = conn.cursor()
        
        # Проверяем и обрабатываем изображения
        images_list = []
        if property_data.images and isinstance(property_data.images, list):
            for img in property_data.images:
                if isinstance(img, str) and img.startswith('/uploads/'):
                    images_list.append(img)
                elif isinstance(img, str) and (img.startswith('http://') or img.startswith('https://')):
                    images_list.append(img)
        
        print(f"Обработанные изображения: {images_list}")
        
        # Преобразуем списки в JSON строки
        images_json = json.dumps(images_list) if images_list else "[]"
        amenities_json = json.dumps(property_data.amenities) if property_data.amenities else "[]"
        
        print(f"Данные для сохранения: title={property_data.title}, price={property_data.price}, city={property_data.city}")
        
        cursor.execute('''
            INSERT INTO properties (
                title, description, property_type, deal_type, price, city, district,
                address, rooms, area, floor, total_floors, year_built,
                latitude, longitude, images, amenities, user_id, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'available')
        ''', (
            property_data.title, property_data.description or "", 
            property_data.property_type, property_data.deal_type, 
            float(property_data.price), property_data.city, property_data.district,
            property_data.address or "", property_data.rooms or "", 
            property_data.area, property_data.floor, property_data.total_floors, 
            property_data.year_built, property_data.latitude, property_data.longitude,
            images_json, amenities_json, admin["id"]
        ))
        
        property_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        print(f"✅ Объект создан с ID: {property_id}")
        
        message = f"🏠 <b>Админ добавил новый объект!</b>\n"
        message += f"Название: {property_data.title}\n"
        message += f"Цена: ${property_data.price:,.0f}\n"
        message += f"Город: {property_data.city}\n"
        message += f"Тип: {property_data.property_type}\n"
        message += f"Админ: {admin['name']}\n"
        message += f"ID: {property_id}"
        send_telegram_notification(message)
        
        log_admin(
            admin["id"],
            "property_created",
            "property",
            property_id,
            f"Админ создал объект: {property_data.title}"
        )
        
        return {
            "success": True,
            "message": "Объект создан успешно", 
            "property_id": property_id,
            "images": images_list
        }
        
    except Exception as e:
        print(f"❌ Error creating property: {e}")
        print(f"❌ Traceback:", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Ошибка: {str(e)}")

@app.post("/api/admin/properties/{property_id}/upload-images")
async def upload_property_images(
    property_id: int,
    images: List[UploadFile] = File([]),
    admin: dict = Depends(get_current_admin)
):
    """Загрузка изображений для существующего объекта"""
    try:
        conn = sqlite3.connect('turkey_realty.db')
        cursor = conn.cursor()
        
        # Проверяем существование объекта
        cursor.execute("SELECT id, images FROM properties WHERE id = ?", (property_id,))
        property_data = cursor.fetchone()
        
        if not property_data:
            conn.close()
            raise HTTPException(status_code=404, detail="Объект не найден")
        
        # Получаем существующие изображения
        existing_images = []
        if property_data[1]:
            try:
                existing_images = json.loads(property_data[1])
            except:
                existing_images = []
        
        # Загружаем новые изображения
        uploaded_images = []
        
        for image in images:
            try:
                # Проверяем размер файла
                image.file.seek(0, 2)
                file_size = image.file.tell()
                image.file.seek(0)
                
                if file_size > MAX_FILE_SIZE:
                    continue
                
                # Проверяем тип файла
                if image.content_type not in ALLOWED_IMAGE_TYPES:
                    continue
                
                # Генерируем уникальное имя файла
                file_extension = image.filename.split('.')[-1] if '.' in image.filename else 'jpg'
                filename = f"{uuid.uuid4().hex}.{file_extension}"
                file_path = UPLOAD_DIR / filename
                
                # Сохраняем файл
                with open(file_path, "wb") as buffer:
                    shutil.copyfileobj(image.file, buffer)
                
                # Добавляем URL к списку изображений
                file_url = f"/uploads/{filename}"
                uploaded_images.append(file_url)
                
            except Exception as e:
                print(f"Ошибка загрузки изображения: {e}")
                continue
        
        # Объединяем старые и новые изображения
        all_images = existing_images + uploaded_images
        
        # Обновляем объект в базе данных
        cursor.execute(
            "UPDATE properties SET images = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (json.dumps(all_images), property_id)
        )
        
        conn.commit()
        conn.close()
        
        return {
            "success": True,
            "message": f"Загружено {len(uploaded_images)} изображений",
            "uploaded_images": uploaded_images,
            "total_images": len(all_images)
        }
        
    except Exception as e:
        print(f"Error uploading images: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка загрузки изображений: {str(e)}")

# Старый эндпоинт для формы (оставляем для совместимости)
@app.post("/api/admin/properties")
async def admin_create_property(
    title: str = Form(...),
    description: Optional[str] = Form(None),
    property_type: str = Form(...),
    deal_type: str = Form(...),
    price: float = Form(...),
    city: str = Form(...),
    district: str = Form(...),
    address: Optional[str] = Form(None),
    rooms: Optional[str] = Form(None),
    area: Optional[float] = Form(None),
    floor: Optional[int] = Form(None),
    total_floors: Optional[int] = Form(None),
    year_built: Optional[int] = Form(None),
    latitude: Optional[float] = Form(None),
    longitude: Optional[float] = Form(None),
    amenities: Optional[str] = Form(None),
    images: List[UploadFile] = File([]),
    admin: dict = Depends(get_current_admin)
):
    """Создание объекта от имени администратора с загрузкой изображений"""
    try:
        conn = sqlite3.connect('turkey_realty.db')
        cursor = conn.cursor()
        
        uploaded_images = []
        
        for image in images:
            try:
                image.file.seek(0, 2)
                file_size = image.file.tell()
                image.file.seek(0)
                
                if file_size > MAX_FILE_SIZE:
                    continue
                
                if image.content_type not in ALLOWED_IMAGE_TYPES:
                    continue
                
                file_extension = image.filename.split('.')[-1] if '.' in image.filename else 'jpg'
                filename = f"{uuid.uuid4().hex}.{file_extension}"
                file_path = UPLOAD_DIR / filename
                
                with open(file_path, "wb") as buffer:
                    shutil.copyfileobj(image.file, buffer)
                
                uploaded_images.append(f"/uploads/{filename}")
                
            except Exception as e:
                print(f"Ошибка загрузки изображения: {e}")
                continue
        
        amenities_list = []
        if amenities:
            amenities_list = [amenity.strip() for amenity in amenities.split(',') if amenity.strip()]
        
        images_json = json.dumps(uploaded_images) if uploaded_images else "[]"
        amenities_json = json.dumps(amenities_list)
        
        cursor.execute('''
            INSERT INTO properties (
                title, description, property_type, deal_type, price, city, district,
                address, rooms, area, floor, total_floors, year_built,
                latitude, longitude, images, amenities, user_id, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'available')
        ''', (
            title, description, property_type, deal_type, price,
            city, district, address, rooms, area,
            floor, total_floors, year_built, latitude,
            longitude, images_json, amenities_json, admin["id"]
        ))
        
        property_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        message = f"🏠 <b>Админ добавил новый объект!</b>\n"
        message += f"Название: {title}\n"
        message += f"Цена: ${price:,.0f}\n"
        message += f"Город: {city}\n"
        message += f"Тип: {property_type}\n"
        message += f"Админ: {admin['name']}\n"
        message += f"ID: {property_id}"
        send_telegram_notification(message)
        
        log_admin(
            admin["id"],
            "property_created",
            "property",
            property_id,
            f"Админ создал объект: {title}"
        )
        
        return {
            "success": True,
            "message": "Объект создан успешно", 
            "property_id": property_id
        }
        
    except Exception as e:
        print(f"Error creating property: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка: {str(e)}")

@app.patch("/api/admin/properties/{property_id}")
async def admin_update_property(
    property_id: int,
    update_data: PropertyAdminUpdate,
    admin: dict = Depends(get_current_admin)
):
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT id FROM properties WHERE id = ?", (property_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Объект не найден")
    
    updates = []
    values = []
    
    if update_data.title is not None:
        updates.append("title = ?")
        values.append(update_data.title)
    
    if update_data.description is not None:
        updates.append("description = ?")
        values.append(update_data.description)
    
    if update_data.price is not None:
        updates.append("price = ?")
        values.append(update_data.price)
    
    if update_data.city is not None:
        updates.append("city = ?")
        values.append(update_data.city)
    
    if update_data.district is not None:
        updates.append("district = ?")
        values.append(update_data.district)
    
    if update_data.status is not None:
        updates.append("status = ?")
        values.append(update_data.status)
    
    if not updates:
        conn.close()
        return {"message": "Нет изменений"}
    
    values.append(property_id)
    query = f"UPDATE properties SET {', '.join(updates)}, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
    
    cursor.execute(query, values)
    conn.commit()
    conn.close()
    
    log_admin(
        admin["id"],
        "property_updated",
        "property",
        property_id,
        f"Обновлены поля: {', '.join([u.split(' =')[0] for u in updates])}"
    )
    
    return {"message": "Объект обновлен успешно"}

@app.put("/api/admin/properties/{property_id}/status")
async def admin_update_property_status(
    property_id: int,
    status_update: PropertyStatusUpdate,
    admin: dict = Depends(get_current_admin)
):
    """Изменение статуса объекта"""
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, title FROM properties WHERE id = ?", (property_id,))
    property_data = cursor.fetchone()
    if not property_data:
        conn.close()
        raise HTTPException(status_code=404, detail="Объект не найден")
    
    cursor.execute("SELECT status FROM properties WHERE id = ?", (property_id,))
    old_status_row = cursor.fetchone()
    old_status = old_status_row[0] if old_status_row else "unknown"
    
    cursor.execute(
        "UPDATE properties SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", 
        (status_update.status, property_id)
    )
    conn.commit()
    conn.close()
    
    log_admin(
        admin["id"], 
        "property_status_changed", 
        "property", 
        property_id, 
        f"status: {old_status} → {status_update.status}, title: {property_data[1]}"
    )
    
    if status_update.status == 'sold':
        message = f"💰 <b>Объект продан!</b>\n"
        message += f"ID: {property_id}\n"
        message += f"Название: {property_data[1]}\n"
        message += f"Админ: {admin['name']}\n"
        send_telegram_notification(message)
    
    return {"message": f"Статус объекта изменен на '{status_update.status}'"}

@app.delete("/api/admin/properties/{property_id}")
async def admin_delete_property(property_id: int, admin: dict = Depends(get_current_admin)):
    """Удаление объекта"""
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, title FROM properties WHERE id = ?", (property_id,))
    property_info = cursor.fetchone()
    if not property_info:
        conn.close()
        raise HTTPException(status_code=404, detail="Объект не найден")
    
    cursor.execute("DELETE FROM properties WHERE id = ?", (property_id,))
    cursor.execute("DELETE FROM favorites WHERE property_id = ?", (property_id,))
    conn.commit()
    conn.close()
    
    log_admin(
        admin["id"], 
        "property_deleted", 
        "property", 
        property_id, 
        f"title={property_info[1]}"
    )
    
    message = f"🗑️ <b>Объект удален!</b>\n"
    message += f"ID: {property_id}\n"
    message += f"Название: {property_info[1]}\n"
    message += f"Админ: {admin['name']}"
    send_telegram_notification(message)
    
    return {"message": "Объект удален навсегда"}

@app.get("/api/admin/users")
async def admin_list_users(
    admin: dict = Depends(get_current_admin),
    role: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    try:
        conn = sqlite3.connect('turkey_realty.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = """
            SELECT id, email, name, phone, role, created_at, last_login, 
                   (SELECT COUNT(*) FROM properties WHERE user_id = users.id) as property_count
            FROM users 
            WHERE 1=1
        """
        params = []
        
        if role:
            query += " AND role = ?"
            params.append(role)
        
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        count_query = "SELECT COUNT(*) FROM users WHERE 1=1"
        count_params = []
        
        if role:
            count_query += " AND role = ?"
            count_params.append(role)
        
        cursor.execute(count_query, count_params)
        total = cursor.fetchone()[0] or 0
        
        conn.close()
        
        users = []
        for r in rows:
            user = dict(r)
            users.append(user)
        
        return {
            "users": users,
            "total": total,
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        print(f"Error in admin_list_users: {e}")
        return {"users": [], "total": 0}

@app.get("/api/admin/users/{user_id}")
async def admin_get_user(user_id: int, admin: dict = Depends(get_current_admin)):
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, email, name, phone, role, created_at, last_login, description,
               (SELECT COUNT(*) FROM properties WHERE user_id = ?) as property_count,
               (SELECT COUNT(*) FROM orders WHERE user_id = ?) as order_count
        FROM users 
        WHERE id = ?
    ''', (user_id, user_id, user_id))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    return {
        "id": row[0],
        "email": row[1],
        "name": row[2],
        "phone": row[3],
        "role": row[4] or "user",
        "created_at": row[5],
        "last_login": row[6],
        "description": row[7],
        "property_count": row[8] or 0,
        "order_count": row[9] or 0
    }

@app.patch("/api/admin/users/{user_id}/role")
async def update_user_role(
    user_id: int, 
    role_update: UserRoleUpdate, 
    admin: dict = Depends(get_current_admin)
):
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, name, email, role FROM users WHERE id = ?", (user_id,))
    user_data = cursor.fetchone()
    if not user_data:
        conn.close()
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    old_role = user_data[3] or "user"
    
    cursor.execute("UPDATE users SET role = ? WHERE id = ?", (role_update.role, user_id))
    conn.commit()
    conn.close()
    
    log_admin(
        admin["id"], 
        "user_role_updated", 
        "user", 
        user_id, 
        f"role: {old_role} → {role_update.role}, user: {user_data[1]} ({user_data[2]})"
    )
    
    message = f"👑 <b>Изменена роль пользователя!</b>\n"
    message += f"Пользователь: {user_data[1]}\n"
    message += f"Email: {user_data[2]}\n"
    message += f"Старая роль: {old_role}\n"
    message += f"Новая роль: {role_update.role}\n"
    message += f"Админ: {admin['name']}"
    send_telegram_notification(message)
    
    return {"message": "Роль пользователя обновлена успешно"}

@app.post("/api/admin/users/{user_id}/toggle-active")
async def toggle_user_active(user_id: int, admin: dict = Depends(get_current_admin)):
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, name, email, is_active FROM users WHERE id = ?", (user_id,))
    user_data = cursor.fetchone()
    if not user_data:
        conn.close()
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    new_status = 0 if user_data[3] else 1
    status_text = "активирован" if new_status else "деактивирован"
    
    cursor.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_status, user_id))
    conn.commit()
    conn.close()
    
    log_admin(
        admin["id"], 
        f"user_{'activated' if new_status else 'deactivated'}", 
        "user", 
        user_id, 
        f"user: {user_data[1]} ({user_data[2]})"
    )
    
    message = f"👤 <b>Пользователь {status_text}!</b>\n"
    message += f"Пользователь: {user_data[1]}\n"
    message += f"Email: {user_data[2]}\n"
    message += f"Статус: {status_text}\n"
    message += f"Админ: {admin['name']}"
    send_telegram_notification(message)
    
    return {"message": f"Пользователь {status_text} успешно"}

@app.get("/api/admin/orders")
async def admin_list_orders(
    admin: dict = Depends(get_current_admin),
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    try:
        conn = sqlite3.connect('turkey_realty.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = """
            SELECT o.*, u.name as user_name, u.email as user_email, 
                   p.title as property_title, p.price as property_price
            FROM orders o 
            LEFT JOIN users u ON u.id = o.user_id 
            LEFT JOIN properties p ON p.id = o.property_id 
            WHERE 1=1
        """
        params = []
        
        if status:
            query += " AND o.status = ?"
            params.append(status)
        
        query += " ORDER BY o.created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        count_query = "SELECT COUNT(*) FROM orders WHERE 1=1"
        count_params = []
        
        if status:
            count_query += " AND status = ?"
            count_params.append(status)
        
        cursor.execute(count_query, count_params)
        total = cursor.fetchone()[0] or 0
        
        orders = []
        for r in rows:
            order = dict(r)
            
            cursor2 = conn.cursor()
            cursor2.execute("SELECT * FROM crypto_invoices WHERE order_id = ?", (order["id"],))
            invoice = cursor2.fetchone()
            if invoice:
                order["invoice"] = dict(invoice)
            orders.append(order)
        
        conn.close()
        
        return {
            "orders": orders,
            "total": total,
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        print(f"Error in admin_list_orders: {e}")
        return {"orders": [], "total": 0}

@app.post("/api/admin/orders/{order_id}/invoice")
async def create_invoice_for_order(
    order_id: int, 
    request: Request, 
    admin: dict = Depends(get_current_admin)
):
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT id, user_id, amount, currency FROM orders WHERE id = ? AND status = 'pending'", 
        (order_id,)
    )
    order = cursor.fetchone()
    if not order:
        conn.close()
        raise HTTPException(status_code=404, detail="Заказ не найден или уже обработан")
    
    cursor.execute("SELECT wallet_address, currency, network FROM crypto_wallet_config WHERE id = 1")
    wallet = cursor.fetchone()
    if not wallet or not wallet[0]:
        conn.close()
        raise HTTPException(status_code=400, detail="Сначала настройте крипто-кошелек в админ-панели")
    
    cursor.execute(
        "INSERT INTO crypto_invoices (order_id, crypto_address, amount, currency, status) VALUES (?, ?, ?, ?, 'pending')",
        (order_id, wallet[0], order[2], wallet[1] or "USDT")
    )
    invoice_id = cursor.lastrowid
    
    cursor.execute("UPDATE orders SET updated_at = CURRENT_TIMESTAMP WHERE id = ?", (order_id,))
    conn.commit()
    conn.close()
    
    log_payment(order_id, invoice_id, "invoice_created", f"amount={order[2]}", request)
    log_admin(admin["id"], "invoice_created", "order", order_id)
    
    message = f"💰 <b>Новый инвойс создан!</b>\n"
    message += f"Заказ ID: {order_id}\n"
    message += f"Сумма: {order[2]} {wallet[1] or 'USDT'}\n"
    message += f"Адрес: {wallet[0]}\n"
    message += f"Сеть: {wallet[2] or 'Не указана'}\n"
    message += f"Инвойс ID: {invoice_id}"
    send_telegram_notification(message)
    
    return {
        "invoice_id": invoice_id,
        "crypto_address": wallet[0],
        "amount": order[2],
        "currency": wallet[1] or "USDT",
        "network": wallet[2]
    }

@app.post("/api/admin/invoices/{invoice_id}/confirm")
async def confirm_invoice(
    invoice_id: int,
    body: InvoiceConfirm,
    request: Request,
    admin: dict = Depends(get_current_admin)
):
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT id, order_id, amount, currency FROM crypto_invoices WHERE id = ? AND status = 'pending'", 
        (invoice_id,)
    )
    invoice = cursor.fetchone()
    if not invoice:
        conn.close()
        raise HTTPException(status_code=404, detail="Инвойс не найден или уже подтвержден")
    
    cursor.execute(
        "UPDATE crypto_invoices SET status = 'confirmed', tx_hash = ?, confirmed_at = CURRENT_TIMESTAMP WHERE id = ?",
        (body.tx_hash, invoice_id)
    )
    cursor.execute(
        "UPDATE orders SET status = 'paid', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (invoice[1],)
    )
    conn.commit()
    conn.close()
    
    log_payment(invoice[1], invoice_id, "payment_confirmed", body.tx_hash, request)
    log_admin(admin["id"], "invoice_confirmed", "invoice", invoice_id)
    
    message = f"✅ <b>Платеж подтвержден!</b>\n"
    message += f"Инвойс ID: {invoice_id}\n"
    message += f"Заказ ID: {invoice[1]}\n"
    message += f"Сумма: {invoice[2]} {invoice[3]}\n"
    message += f"TX Hash: {body.tx_hash}"
    send_telegram_notification(message)
    
    return {"message": "Оплата подтверждена успешно"}

@app.get("/api/admin/crypto-wallet")
async def get_crypto_wallet(admin: dict = Depends(get_current_admin)):
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    cursor.execute("SELECT wallet_address, currency, network, updated_at FROM crypto_wallet_config WHERE id = 1")
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return {
            "wallet_address": row[0] or "",
            "currency": row[1] or "USDT",
            "network": row[2] or "",
            "updated_at": row[3]
        }
    
    return {"wallet_address": "", "currency": "USDT", "network": "", "updated_at": None}

@app.put("/api/admin/crypto-wallet")
async def set_crypto_wallet(cfg: CryptoWalletConfig, admin: dict = Depends(get_current_admin)):
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    
    cursor.execute(
        "INSERT OR REPLACE INTO crypto_wallet_config (id, wallet_address, currency, network, updated_at) VALUES (1, ?, ?, ?, CURRENT_TIMESTAMP)",
        (cfg.wallet_address, cfg.currency, cfg.network)
    )
    
    conn.commit()
    conn.close()
    
    log_admin(
        admin["id"], 
        "crypto_wallet_updated", 
        details=f"address: {cfg.wallet_address[:20]}..., currency: {cfg.currency}, network: {cfg.network or 'Не указана'}"
    )
    
    message = f"👛 <b>Обновлен крипто-кошелек!</b>\n"
    message += f"Валюта: {cfg.currency}\n"
    message += f"Сеть: {cfg.network or 'Не указана'}\n"
    message += f"Адрес: {cfg.wallet_address[:20]}...\n"
    message += f"Админ: {admin['name']}"
    send_telegram_notification(message)
    
    return {"message": "Настройки кошелька обновлены успешно"}

@app.get("/api/admin/logs")
async def admin_audit_logs(
    admin: dict = Depends(get_current_admin),
    entity_type: Optional[str] = None,
    limit: int = 200,
    offset: int = 0
):
    try:
        conn = sqlite3.connect('turkey_realty.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = """
            SELECT l.*, u.name as admin_name 
            FROM admin_audit_logs l 
            LEFT JOIN users u ON u.id = l.admin_id 
            WHERE 1=1
        """
        params = []
        
        if entity_type:
            query += " AND l.entity_type = ?"
            params.append(entity_type)
        
        query += " ORDER BY l.created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        count_query = "SELECT COUNT(*) FROM admin_audit_logs WHERE 1=1"
        count_params = []
        
        if entity_type:
            count_query += " AND entity_type = ?"
            count_params.append(entity_type)
        
        cursor.execute(count_query, count_params)
        total = cursor.fetchone()[0] or 0
        
        conn.close()
        
        logs = []
        for r in rows:
            logs.append(dict(r))
        
        return {
            "logs": logs,
            "total": total,
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        print(f"Error in admin_audit_logs: {e}")
        return {"logs": [], "total": 0}

@app.get("/api/admin/payment-logs")
async def get_payment_logs(
    admin: dict = Depends(get_current_admin),
    limit: int = 100,
    offset: int = 0
):
    try:
        conn = sqlite3.connect('turkey_realty.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM payment_logs 
            ORDER BY created_at DESC 
            LIMIT ? OFFSET ?
        """, (limit, offset))
        
        rows = cursor.fetchall()
        
        cursor.execute("SELECT COUNT(*) FROM payment_logs")
        total = cursor.fetchone()[0] or 0
        
        conn.close()
        
        logs = []
        for r in rows:
            logs.append(dict(r))
        
        return {
            "logs": logs,
            "total": total,
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        print(f"Error in get_payment_logs: {e}")
        return {"logs": [], "total": 0}

@app.get("/api/support/conversations")
async def list_support_conversations(admin: dict = Depends(get_current_admin)):
    try:
        conn = sqlite3.connect('turkey_realty.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT c.*, u.name as user_name, u.email,
                   (SELECT COUNT(*) FROM support_messages WHERE conversation_id = c.id) as message_count,
                   (SELECT body FROM support_messages WHERE conversation_id = c.id ORDER BY created_at DESC LIMIT 1) as last_message
            FROM support_conversations c 
            JOIN users u ON u.id = c.user_id 
            ORDER BY c.updated_at DESC
        """)
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(r) for r in rows]
        
    except Exception as e:
        print(f"Error in list_support_conversations: {e}")
        return []

@app.post("/api/support/conversations/{conversation_id}/assign")
async def assign_support_conversation(conversation_id: int, admin: dict = Depends(get_current_admin)):
    conn = sqlite3.connect('turkey_realty.db')
    cursor = conn.cursor()
    
    cursor.execute(
        "UPDATE support_conversations SET assigned_to = ?, status = 'active' WHERE id = ?",
        (admin["id"], conversation_id)
    )
    conn.commit()
    conn.close()
    
    log_admin(admin["id"], "support_conversation_assigned", "support_conversation", conversation_id)
    
    return {"message": "Диалог назначен успешно"}

# --- MIDDLEWARE FOR TRACKING ---

@app.middleware("http")
async def track_page_view(request: Request, call_next):
    response = await call_next(request)
    
    if request.method == "GET" and not request.url.path.startswith(("/static", "/admin_panel", "/api/admin", "/api/me")):
        try:
            auth = request.headers.get("Authorization")
            user_id = None
            
            if auth and auth.startswith("Bearer "):
                try:
                    payload = jwt.decode(auth[7:], SECRET_KEY, algorithms=[ALGORITHM])
                    user_id = payload.get("user_id")
                except:
                    pass
            
            conn = sqlite3.connect('turkey_realty.db')
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO page_views (path, user_id, ip_address, user_agent) VALUES (?, ?, ?, ?)",
                (request.url.path, user_id, request.client.host, request.headers.get('user-agent', ''))
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Page view tracking error: {e}")
    
    return response

# --- STATIC FILES ---

app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

@app.get("/")
async def read_root():
    return FileResponse("static/index.html")

@app.get("/admin_panel")
async def admin_panel():
    return FileResponse("static/admin_panel.html")

@app.get("/profile")
async def profile():
    return FileResponse("static/profile.html")

@app.get("/property/{property_id}")
async def property_detail(property_id: int):
    return FileResponse("static/property.html")

@app.get("/add-property")
async def add_property():
    return FileResponse("static/add-property.html")

# --- SESSION ENDPOINT ---
@app.get("/api/check-session")
async def check_session(auth: HTTPAuthorizationCredentials = Depends(security)):
    """Проверка сессии пользователя"""
    try:
        payload = jwt.decode(auth.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        if user_id is None:
            return {"valid": False}
        
        conn = sqlite3.connect('turkey_realty.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, email, name, phone, role, avatar, description, is_active 
            FROM users WHERE id = ?
        ''', (user_id,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return {"valid": False}
        
        if not row[7]:
            return {"valid": False, "message": "Аккаунт деактивирован"}
        
        return {
            "valid": True,
            "user": {
                "id": row[0],
                "email": row[1],
                "name": row[2],
                "phone": row[3],
                "role": row[4] or "user",
                "avatar": row[5],
                "description": row[6]
            }
        }
    except jwt.ExpiredSignatureError:
        return {"valid": False, "message": "Срок действия токена истек"}
    except jwt.InvalidTokenError:
        return {"valid": False, "message": "Недействительный токен"}
    except Exception as e:
        print(f"Session check error: {e}")
        return {"valid": False, "message": "Ошибка проверки сессии"}

# Запуск приложения
if __name__ == "__main__":
    import uvicorn
    print("🚀 Запуск BROKEROK API v2.0.0")
    print("📁 База данных: turkey_realty.db")
    print("🔗 Адрес: http://localhost:8000")
    print("👨‍💼 Админ: admin@brokeroke.com / admin123")
    print("=" * 50)
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )