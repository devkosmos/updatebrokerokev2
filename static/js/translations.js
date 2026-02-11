const translations = {
    ru: {
        nav_buy: "Купить",
        nav_rent: "Снять",
        nav_about: "О нас",
        nav_contact: "Контакты",
        hero_title: "Найдите идеальный дом в Турции",
        hero_subtitle: "Премиальная недвижимость в лучших районах Стамбула, Анталии и других городов",
        search_buy: "Купить",
        search_rent: "Снять",
        search_placeholder: "Город, район или ЖК...",
        search_btn: "Найти",
        section_featured: "Рекомендуемые объекты",
        section_featured_sub: "Лучшие предложения, отобранные нашими экспертами",
        footer_about: "BROKEROK — ваш надежный партнер на рынке недвижимости Турции. Мы помогаем найти дом мечты и сопровождаем сделку на всех этапах.",
        footer_links: "Быстрые ссылки",
        footer_contacts: "Контакты",
        login: "Войти",
        register: "Регистрация",
        logout: "Выйти",
        profile: "Профиль",
        admin: "Админ",
        status_sold: "ПРОДАНО",
        crypto_pay: "Купить за крипту",
        add_fav: "В избранное",
        in_fav: "В избранном",
        call: "Позвонить"
    },
    en: {
        nav_buy: "Buy",
        nav_rent: "Rent",
        nav_about: "About",
        nav_contact: "Contact",
        hero_title: "Find Your Perfect Home in Turkey",
        hero_subtitle: "Premium real estate in the best areas of Istanbul, Antalya, and other cities",
        search_buy: "Buy",
        search_rent: "Rent",
        search_placeholder: "City, district or complex...",
        search_btn: "Search",
        section_featured: "Featured Properties",
        section_featured_sub: "Best offers selected by our experts",
        footer_about: "BROKEROK is your reliable partner in the Turkish real estate market. We help you find your dream home and support the deal at all stages.",
        footer_links: "Quick Links",
        footer_contacts: "Contacts",
        login: "Login",
        register: "Register",
        logout: "Logout",
        profile: "Profile",
        admin: "Admin",
        status_sold: "SOLD",
        crypto_pay: "Buy with Crypto",
        add_fav: "Add to Fav",
        in_fav: "In Favorites",
        call: "Call"
    },
    tr: {
        nav_buy: "Satın Al",
        nav_rent: "Kiralık",
        nav_about: "Hakkımızda",
        nav_contact: "İletişim",
        hero_title: "Türkiye'deki Mükemmel Evinizi Bulun",
        hero_subtitle: "İstanbul, Antalya ve diğer şehirlerin en iyi bölgelerinde premium emlak",
        search_buy: "Satın Al",
        search_rent: "Kiralık",
        search_placeholder: "Şehir, ilçe veya site...",
        search_btn: "Ara",
        section_featured: "Öne Çıkan İlanlar",
        section_featured_sub: "Uzmanlarımız tarafından seçilen en iyi teklifler",
        footer_about: "BROKEROK, Türkiye emlak piyasasındaki güvenilir ortağınızdır. Hayalinizdeki evi bulmanıza yardımcı oluyoruz.",
        footer_links: "Hızlı Bağlantılar",
        footer_contacts: "İletişim",
        login: "Giriş Yap",
        register: "Kayıt Ol",
        logout: "Çıkış Yap",
        profile: "Profil",
        admin: "Admin",
        status_sold: "SATILDI",
        crypto_pay: "Kripto ile Al",
        add_fav: "Favoriye Ekle",
        in_fav: "Favorilerde",
        call: "Ara"
    }
};

function setLanguage(lang) {
    localStorage.setItem('lang', lang);
    applyTranslations();
}

function applyTranslations() {
    const lang = localStorage.getItem('lang') || 'ru';
    const t = translations[lang];
    
    document.querySelectorAll('[data-t]').forEach(el => {
        const key = el.getAttribute('data-t');
        if (t[key]) {
            if (el.tagName === 'INPUT' && el.placeholder) {
                el.placeholder = t[key];
            } else {
                el.innerHTML = t[key];
            }
        }
    });
}

document.addEventListener('DOMContentLoaded', applyTranslations);
