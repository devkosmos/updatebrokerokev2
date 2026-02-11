let currentDealType = 'sale';

document.addEventListener('DOMContentLoaded', () => {
    loadCities();
    loadProperties();
    checkAuth();
});

function showModal(id) { document.getElementById(id).classList.add('show'); }
function closeModal(id) { document.getElementById(id).classList.remove('show'); }

async function checkAuth() {
    const token = localStorage.getItem('token');
    const userData = localStorage.getItem('user');
    const authBtns = document.getElementById('authButtons');
    const userMenu = document.getElementById('userMenu');
    
    if (!token || !userData) {
        // Нет токена или данных пользователя
        authBtns.style.display = 'flex';
        if (userMenu) userMenu.classList.remove('active');
        return;
    }
    
    try {
        // Проверяем валидность токена через API
        const response = await fetch('/api/check-session', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        const data = await response.json();
        
        if (data.valid && data.user) {
            // Токен валиден, обновляем данные
            localStorage.setItem('user', JSON.stringify(data.user));
            authBtns.style.display = 'none';
            userMenu.classList.add('active');
            document.getElementById('userInitials').textContent = data.user.name[0].toUpperCase();
        } else {
            // Токен невалиден, очищаем
            localStorage.removeItem('token');
            localStorage.removeItem('user');
            authBtns.style.display = 'flex';
            userMenu.classList.remove('active');
        }
    } catch (error) {
        console.error('Ошибка проверки авторизации:', error);
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        authBtns.style.display = 'flex';
        if (userMenu) userMenu.classList.remove('active');
    }
}

async function handleLogin(e) {
    e.preventDefault();
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;
    
    try {
        const res = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        
        if (res.ok) {
            const data = await res.json();
            // Сохраняем в том же формате, что и при проверке
            localStorage.setItem('token', data.access_token);
            localStorage.setItem('user', JSON.stringify(data.user));
            location.reload();
        } else { 
            const error = await res.json();
            alert(error.detail || 'Ошибка входа'); 
        }
    } catch (err) { 
        console.error('Ошибка входа:', err);
        alert('Ошибка сервера'); 
    }
}

async function handleRegister(e) {
    e.preventDefault();
    const name = document.getElementById('regName').value;
    const email = document.getElementById('regEmail').value;
    const password = document.getElementById('regPassword').value;
    
    try {
        const res = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, email, password })
        });
        
        if (res.ok) {
            const data = await res.json();
            // Сохраняем в том же формате, что и при проверке
            localStorage.setItem('token', data.access_token);
            localStorage.setItem('user', JSON.stringify(data.user));
            location.reload();
        } else { 
            const error = await res.json();
            alert(error.detail || 'Ошибка регистрации'); 
        }
    } catch (err) { 
        console.error('Ошибка регистрации:', err);
        alert('Ошибка сервера'); 
    }
}

function logout() {
    // Очищаем все связанные с авторизацией данные
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    localStorage.removeItem('access_token'); // На всякий случай удаляем и старый ключ
    localStorage.removeItem('user_data');
    location.reload();
}

async function loadCities() {
    try {
        const res = await fetch('/api/cities');
        if (res.ok) {
            const cities = await res.json();
            const select = document.getElementById('citySelect');
            select.innerHTML = '<option value="">Все города</option>';
            cities.forEach(c => {
                const opt = document.createElement('option');
                opt.value = c.value; 
                opt.textContent = c.name;
                select.appendChild(opt);
            });
        }
    } catch (error) {
        console.error('Ошибка загрузки городов:', error);
    }
}

function switchDealType(type, btn) {
    currentDealType = type;
    document.querySelectorAll('.search-tab').forEach(t => t.classList.remove('active'));
    btn.classList.add('active');
    loadProperties();
}

function filterByDealType(type) {
    currentDealType = type;
    loadProperties();
}

async function loadProperties() {
    try {
        const res = await fetch(`/api/properties?deal_type=${currentDealType}`);
        if (res.ok) {
            const data = await res.json();
            renderProperties(data.properties || []);
        }
    } catch (error) {
        console.error('Ошибка загрузки объектов:', error);
        const container = document.getElementById('propertiesContainer');
        container.innerHTML = '<p style="grid-column: 1/-1; text-align: center; padding: 40px; color: #666;">Ошибка загрузки объектов</p>';
    }
}

async function handleSearch(e) {
    e.preventDefault();
    const city = document.getElementById('citySelect').value;
    const type = document.getElementById('typeSelect').value;
    const maxPrice = document.getElementById('maxPrice').value;
    
    let url = `/api/properties?deal_type=${currentDealType}`;
    if (city) url += `&city=${city}`;
    if (type) url += `&property_type=${type}`;
    if (maxPrice) url += `&max_price=${maxPrice}`;
    
    try {
        const res = await fetch(url);
        if (res.ok) {
            const data = await res.json();
            renderProperties(data.properties || []);
        }
    } catch (error) {
        console.error('Ошибка поиска:', error);
        alert('Ошибка при поиске объектов');
    }
}

function renderProperties(props) {
    const container = document.getElementById('propertiesContainer');
    if (!props || !props.length) {
        container.innerHTML = '<p style="grid-column: 1/-1; text-align: center; padding: 40px; color: #666;">Ничего не найдено</p>';
        return;
    }
    
    container.innerHTML = props.map(p => `
        <div class="card" onclick="location.href='/property/${p.id}'" style="${p.status === 'sold' ? 'opacity: 0.8;' : ''}">
            <div class="img-container">
                <img src="${p.images && p.images[0] ? p.images[0] : '/static/images/4Eaa6DysGCj9.jpg'}" 
                     class="card-img" style="${p.status === 'sold' ? 'filter: grayscale(0.8);' : ''}">
                <div class="card-badge">${p.deal_type === 'sale' ? 'Продажа' : 'Аренда'}</div>
                ${p.status === 'sold' ? '<div class="card-badge" style="top: 50px; background: #ef4444;">ПРОДАНО</div>' : ''}
            </div>
            <div class="card-body">
                <div class="card-price">$${(p.price || 0).toLocaleString()}</div>
                <div class="card-title">${p.title || 'Без названия'}</div>
                <div style="font-size: 13px; color: #666; display: flex; justify-content: space-between; align-items: center;">
                    <span><i class="fas fa-map-marker-alt"></i> ${p.city || 'Не указан'}</span>
                    <span><i class="fas fa-eye"></i> ${p.views || 0}</span>
                </div>
            </div>
        </div>
    `).join('');
}

// Также добавьте эти функции для работы с избранным:
async function toggleFavorite(propertyId, event) {
    event.stopPropagation(); // Чтобы не срабатывал клик по карточке
    
    const token = localStorage.getItem('token');
    if (!token) {
        alert('Для добавления в избранное необходимо войти в аккаунт');
        showModal('loginModal');
        return;
    }
    
    const button = event.currentTarget;
    const isFavorite = button.classList.contains('favorite-active');
    
    try {
        let response;
        if (isFavorite) {
            response = await fetch(`/api/favorites/${propertyId}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
        } else {
            response = await fetch(`/api/favorites/${propertyId}`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
        }
        
        if (response.ok) {
            const result = await response.json();
            if (isFavorite) {
                button.classList.remove('favorite-active');
                button.innerHTML = '<i class="far fa-heart"></i>';
                button.title = 'Добавить в избранное';
            } else {
                button.classList.add('favorite-active');
                button.innerHTML = '<i class="fas fa-heart"></i>';
                button.title = 'Удалить из избранного';
            }
        }
    } catch (error) {
        console.error('Ошибка избранного:', error);
        alert('Ошибка при работе с избранным');
    }
}

// Обновите функцию renderProperties, чтобы добавить кнопку избранного:
function renderProperties(props) {
    const container = document.getElementById('propertiesContainer');
    if (!props || !props.length) {
        container.innerHTML = '<p style="grid-column: 1/-1; text-align: center; padding: 40px; color: #666;">Ничего не найдено</p>';
        return;
    }
    
    container.innerHTML = props.map(p => `
        <div class="card" onclick="location.href='/property/${p.id}'" style="${p.status === 'sold' ? 'opacity: 0.8;' : ''}">
            <div class="img-container">
                <img src="${p.images && p.images[0] ? p.images[0] : '/static/images/4Eaa6DysGCj9.jpg'}" 
                     class="card-img" style="${p.status === 'sold' ? 'filter: grayscale(0.8);' : ''}">
                <div class="card-badge">${p.deal_type === 'sale' ? 'Продажа' : 'Аренда'}</div>
                ${p.status === 'sold' ? '<div class="card-badge" style="top: 50px; background: #ef4444;">ПРОДАНО</div>' : ''}
                <button class="favorite-btn" onclick="toggleFavorite(${p.id}, event)" title="Добавить в избранное">
                    <i class="far fa-heart"></i>
                </button>
            </div>
            <div class="card-body">
                <div class="card-price">$${(p.price || 0).toLocaleString()}</div>
                <div class="card-title">${p.title || 'Без названия'}</div>
                <div style="font-size: 13px; color: #666; display: flex; justify-content: space-between; align-items: center;">
                    <span><i class="fas fa-map-marker-alt"></i> ${p.city || 'Не указан'}</span>
                    <span><i class="fas fa-eye"></i> ${p.views || 0}</span>
                </div>
            </div>
        </div>
    `).join('');
}

// Добавьте стили для кнопки избранного в CSS:
const style = document.createElement('style');
style.textContent = `
    .favorite-btn {
        position: absolute;
        top: 10px;
        right: 10px;
        background: white;
        border: none;
        width: 36px;
        height: 36px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        cursor: pointer;
        box-shadow: 0 2px 5px rgba(0,0,0,0.2);
        z-index: 10;
        transition: all 0.2s;
    }
    
    .favorite-btn:hover {
        transform: scale(1.1);
        background: #f8fafc;
    }
    
    .favorite-btn i {
        font-size: 18px;
        color: #64748b;
    }
    
    .favorite-btn.favorite-active i {
        color: #dc2626;
    }
    
    .favorite-btn:hover i {
        color: #dc2626;
    }
`;
document.head.appendChild(style);