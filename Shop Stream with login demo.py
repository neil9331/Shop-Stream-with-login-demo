"""
ShopStream v2 — e-commerce demo with login/signup and a persistent cart (SQLite).

Run:  pip install streamlit
      streamlit run app.py

Everything is in this one file: the SQLite database code first, then the app.

Builds on Part I: same homepage, catalogue, deals, recommendations, video,
reviews and newsletter. New in v2:
  • Sign up / log in (passwords hashed with PBKDF2 + salt, stored in SQLite)
  • Account page: profile, password change, order history
  • Cart saved in SQLite per user — survives page reloads and new visits
  • Guests can still shop; their cart is merged into the account on login
Product and review data is still simulated (seeded random).
"""
import hashlib
import hmac
import os
import random
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone

import streamlit as st

# ============================================================================
# DATABASE LAYER (SQLite): users, login sessions, cart, orders, newsletter
# Passwords are hashed with PBKDF2-SHA256 + a random per-user salt.
# ============================================================================
DB_PATH = os.getenv("SHOPSTREAM_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                   "shopstream.db"))
SESSION_DAYS = 7
PBKDF2_ITERATIONS = 200_000

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    email         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    full_name     TEXT    NOT NULL,
    password_hash TEXT    NOT NULL,
    salt          TEXT    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS cart_items (
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    product_id INTEGER NOT NULL,
    quantity   INTEGER NOT NULL CHECK (quantity > 0),
    unit_price REAL    NOT NULL,
    added_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user_id, product_id)
);
CREATE TABLE IF NOT EXISTS orders (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    total      REAL    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS order_items (
    order_id   INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    product_id INTEGER NOT NULL,
    quantity   INTEGER NOT NULL,
    unit_price REAL    NOT NULL
);
CREATE TABLE IF NOT EXISTS subscribers (
    email      TEXT PRIMARY KEY COLLATE NOCASE,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


@contextmanager
def db_connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def db_init_db():
    with db_connect() as conn:
        conn.executescript(SCHEMA)


# ---------------------------------------------------------------------------
# Users & authentication
# ---------------------------------------------------------------------------
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
USERNAME_RE = re.compile(r"[A-Za-z0-9_.]{3,30}")


def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt),
                               PBKDF2_ITERATIONS).hex()


def db_create_user(username: str, email: str, full_name: str, password: str):
    """Return (user_id, None) on success or (None, error_message)."""
    username, email, full_name = username.strip(), email.strip().lower(), full_name.strip()
    if not USERNAME_RE.fullmatch(username):
        return None, "Username must be 3–30 characters: letters, numbers, _ or ."
    if not EMAIL_RE.fullmatch(email):
        return None, "Please enter a valid email address."
    if not full_name:
        return None, "Please enter your name."
    if len(password) < 8:
        return None, "Password must be at least 8 characters."
    salt = secrets.token_hex(16)
    try:
        with db_connect() as conn:
            cur = conn.execute(
                "INSERT INTO users (username, email, full_name, password_hash, salt) "
                "VALUES (?, ?, ?, ?, ?)",
                (username, email, full_name, _hash_password(password, salt), salt))
            return cur.lastrowid, None
    except sqlite3.IntegrityError:
        return None, "That username or email is already registered."


def db_authenticate(login: str, password: str):
    """Login with username OR email. Returns the user row or None."""
    with db_connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ? OR email = ?",
                           (login.strip(), login.strip().lower())).fetchone()
    if row and hmac.compare_digest(row["password_hash"], _hash_password(password, row["salt"])):
        return row
    return None


def db_get_user(user_id: int):
    with db_connect() as conn:
        return conn.execute("SELECT id, username, email, full_name, created_at FROM users "
                            "WHERE id = ?", (user_id,)).fetchone()


def db_update_profile(user_id: int, full_name: str, email: str):
    email = email.strip().lower()
    if not full_name.strip():
        return "Name can't be empty."
    if not EMAIL_RE.fullmatch(email):
        return "Please enter a valid email address."
    try:
        with db_connect() as conn:
            conn.execute("UPDATE users SET full_name = ?, email = ? WHERE id = ?",
                         (full_name.strip(), email, user_id))
    except sqlite3.IntegrityError:
        return "That email is already used by another account."
    return None


def db_change_password(user_id: int, current: str, new: str):
    with db_connect() as conn:
        row = conn.execute("SELECT password_hash, salt FROM users WHERE id = ?",
                           (user_id,)).fetchone()
        if not row or not hmac.compare_digest(row["password_hash"],
                                              _hash_password(current, row["salt"])):
            return "Current password is incorrect."
        if len(new) < 8:
            return "New password must be at least 8 characters."
        salt = secrets.token_hex(16)
        conn.execute("UPDATE users SET password_hash = ?, salt = ? WHERE id = ?",
                     (_hash_password(new, salt), salt, user_id))
        # sign out every other device
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    return None


# ---------------------------------------------------------------------------
# Login sessions (keep users signed in across page reloads)
# ---------------------------------------------------------------------------
def _utcnow() -> datetime:
    # naive UTC timestamp, so stored ISO strings compare correctly
    return datetime.now(timezone.utc).replace(tzinfo=None)


def db_create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires = (_utcnow() + timedelta(days=SESSION_DAYS)).isoformat()
    with db_connect() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (_utcnow().isoformat(),))
        conn.execute("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
                     (token, user_id, expires))
    return token


def db_user_for_session(token: str):
    if not token:
        return None
    with db_connect() as conn:
        row = conn.execute("SELECT user_id FROM sessions WHERE token = ? AND expires_at > ?",
                           (token, _utcnow().isoformat())).fetchone()
    return db_get_user(row["user_id"]) if row else None


def db_delete_session(token: str):
    with db_connect() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))


# ---------------------------------------------------------------------------
# Cart
# ---------------------------------------------------------------------------
def db_get_cart(user_id: int) -> list:
    with db_connect() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT product_id, quantity, unit_price FROM cart_items "
            "WHERE user_id = ? ORDER BY added_at", (user_id,))]


def db_add_to_cart(user_id: int, product_id: int, unit_price: float, qty: int = 1):
    """Add qty of a product; if already in the cart, increase the quantity and keep
    the lower of the two prices (so a Deal-of-the-Day price isn't overwritten)."""
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO cart_items (user_id, product_id, quantity, unit_price) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(user_id, product_id) DO UPDATE SET "
            "quantity = quantity + excluded.quantity, "
            "unit_price = MIN(unit_price, excluded.unit_price)",
            (user_id, product_id, qty, unit_price))


def db_set_quantity(user_id: int, product_id: int, qty: int):
    with db_connect() as conn:
        if qty <= 0:
            conn.execute("DELETE FROM cart_items WHERE user_id = ? AND product_id = ?",
                         (user_id, product_id))
        else:
            conn.execute("UPDATE cart_items SET quantity = ? WHERE user_id = ? AND product_id = ?",
                         (qty, user_id, product_id))


def db_clear_cart(user_id: int):
    with db_connect() as conn:
        conn.execute("DELETE FROM cart_items WHERE user_id = ?", (user_id,))


# ---------------------------------------------------------------------------
# Orders (demo checkout — no payment)
# ---------------------------------------------------------------------------
def db_place_order(user_id: int):
    """Move the cart into a new order. Returns (order_id, total) or (None, 0) if empty."""
    with db_connect() as conn:
        items = conn.execute("SELECT product_id, quantity, unit_price FROM cart_items "
                             "WHERE user_id = ?", (user_id,)).fetchall()
        if not items:
            return None, 0.0
        total = round(sum(i["quantity"] * i["unit_price"] for i in items), 2)
        order_id = conn.execute("INSERT INTO orders (user_id, total) VALUES (?, ?)",
                                (user_id, total)).lastrowid
        conn.executemany("INSERT INTO order_items VALUES (?, ?, ?, ?)",
                         [(order_id, i["product_id"], i["quantity"], i["unit_price"]) for i in items])
        conn.execute("DELETE FROM cart_items WHERE user_id = ?", (user_id,))
    return order_id, total


def db_get_orders(user_id: int) -> list:
    with db_connect() as conn:
        orders = [dict(o) for o in conn.execute(
            "SELECT id, total, created_at FROM orders WHERE user_id = ? ORDER BY id DESC",
            (user_id,))]
        for o in orders:
            o["items"] = [dict(r) for r in conn.execute(
                "SELECT product_id, quantity, unit_price FROM order_items WHERE order_id = ?",
                (o["id"],))]
    return orders


# ---------------------------------------------------------------------------
# Newsletter
# ---------------------------------------------------------------------------
def db_subscribe(email: str) -> str:
    """Returns 'ok', 'exists' or 'invalid'."""
    email = email.strip().lower()
    if not EMAIL_RE.fullmatch(email):
        return "invalid"
    try:
        with db_connect() as conn:
            conn.execute("INSERT INTO subscribers (email) VALUES (?)", (email,))
        return "ok"
    except sqlite3.IntegrityError:
        return "exists"


# ============================================================================
# STREAMLIT APP
# ============================================================================

# ----------------------------------------------------------------------------
# Page config
# ----------------------------------------------------------------------------
st.set_page_config(page_title="ShopStream", page_icon="🛍️", layout="wide")

CATEGORIES = ["Electronics", "Fashion", "Home", "Toys"]
CATEGORY_ICONS = {"Electronics": "💻", "Fashion": "👗", "Home": "🏠", "Toys": "🧸"}
CATEGORY_COLORS = {"Electronics": "1e3a8a", "Fashion": "9d174d", "Home": "065f46", "Toys": "9a3412"}

# ----------------------------------------------------------------------------
# Custom CSS
# ----------------------------------------------------------------------------
st.markdown(
    """
<style>
:root{
  --accent:#ff4b4b; --accent-2:#ff8a00; --card:#1a1f2b; --card-border:#2a3142;
  --muted:#9aa3b5; --text:#f2f4f8; --sale:#e11d48; --ok:#22c55e;
}
.block-container{padding-top:1.2rem; max-width:1300px;}

/* Navigation bar */
.navbar{display:flex; align-items:center; justify-content:space-between;
  background:linear-gradient(90deg,#111827,#1f2937); padding:14px 24px;
  border-radius:14px; border:1px solid var(--card-border); margin-bottom:14px;}
.brand{font-size:1.6rem; font-weight:800; color:var(--text); letter-spacing:.5px;}
.brand span{background:linear-gradient(90deg,var(--accent),var(--accent-2));
  -webkit-background-clip:text; -webkit-text-fill-color:transparent;}
.nav-links a{color:var(--muted); margin-left:22px; text-decoration:none; font-weight:600;}
.nav-links a:hover{color:var(--text);}
.cart-pill{background:var(--accent); color:#fff; padding:6px 14px; border-radius:999px;
  font-weight:700; margin-left:22px;}

/* Hero */
.hero{background:linear-gradient(120deg,#ff4b4b 0%,#ff8a00 55%,#ffc300 100%);
  border-radius:18px; padding:48px 40px; color:#fff; margin:8px 0 26px 0;
  box-shadow:0 10px 30px rgba(255,75,75,.25);}
.hero h1{font-size:2.6rem; margin:0 0 8px 0; color:#fff; font-weight:800;}
.hero p{font-size:1.15rem; margin:0 0 18px 0; opacity:.95;}
.hero .cta{display:inline-block; background:#111827; color:#fff; padding:10px 22px;
  border-radius:10px; font-weight:700;}
.hero .badge{display:inline-block; background:rgba(255,255,255,.2); padding:4px 12px;
  border-radius:999px; font-size:.85rem; margin-bottom:12px; font-weight:600;}

/* Section titles */
.section-title{font-size:1.6rem; font-weight:800; color:var(--text);
  border-bottom:2px solid var(--card-border); padding-bottom:8px; margin:30px 0 16px 0;}

/* Product card */
.product-card{background:var(--card); border:1px solid var(--card-border);
  border-radius:14px; padding:12px; transition:transform .15s ease, box-shadow .15s ease;
  height:100%;}
.product-card:hover{transform:translateY(-4px); box-shadow:0 10px 24px rgba(0,0,0,.35);}
.product-card img{width:100%; aspect-ratio:1/1; object-fit:cover; border-radius:10px;}
.product-name{font-weight:700; color:var(--text); margin:10px 0 4px 0; font-size:.98rem;}
.product-cat{color:var(--muted); font-size:.78rem; text-transform:uppercase; letter-spacing:.6px;}
.price-row{margin:6px 0; display:flex; align-items:center; gap:8px; flex-wrap:wrap;}
.price{color:var(--accent); font-weight:800; font-size:1.1rem;}
.old-price{color:var(--muted); text-decoration:line-through; font-size:.9rem;}
.sale-badge{background:var(--sale); color:#fff; font-size:.7rem; font-weight:800;
  padding:2px 7px; border-radius:5px;}
.rating{color:#fbbf24; font-size:.9rem;}
.rating span{color:var(--muted); margin-left:4px;}

/* Deal of the day */
.deal{display:flex; gap:28px; align-items:center; background:linear-gradient(120deg,#1e1b4b,#312e81);
  border:1px solid #4338ca; border-radius:18px; padding:26px; flex-wrap:wrap;}
.deal img{width:260px; max-width:100%; border-radius:14px;}
.deal h2{color:#fff; margin:6px 0;}
.deal .big-price{font-size:2.2rem; font-weight:800; color:#fde047;}
.deal .timer{background:rgba(255,255,255,.12); color:#fff; padding:6px 12px;
  border-radius:8px; display:inline-block; font-weight:700; margin-top:8px;}

/* Reviews */
.review{background:var(--card); border:1px solid var(--card-border); border-left:4px solid var(--accent);
  border-radius:12px; padding:16px; height:100%;}
.review .who{font-weight:700; color:var(--text);}
.review .text{color:#d1d5db; font-style:italic; margin:8px 0;}
.review .meta{color:var(--muted); font-size:.8rem;}

/* Newsletter */
.newsletter{background:linear-gradient(120deg,#064e3b,#065f46); border-radius:18px;
  padding:26px 30px; color:#fff; margin-top:10px;}
.newsletter h3{margin:0 0 4px 0; color:#fff;}

.footer{text-align:center; color:var(--muted); padding:30px 0 10px 0; font-size:.85rem;}

/* Buttons */
.stButton>button{border-radius:10px; font-weight:700; width:100%;
  border:1px solid var(--card-border);}
.stButton>button:hover{border-color:var(--accent); color:var(--accent);}

@media (max-width: 768px){
  .hero{padding:30px 22px;} .hero h1{font-size:1.8rem;}
  .nav-links{display:none;}
}
</style>
""",
    unsafe_allow_html=True,
)


# ----------------------------------------------------------------------------
# Simulated data
# ----------------------------------------------------------------------------
ADJECTIVES = ["Smart", "Classic", "Premium", "Eco", "Ultra", "Cozy", "Pro", "Mini"]
NOUNS = {
    "Electronics": ["Headphones", "Smartwatch", "Speaker", "Tablet", "Camera", "Charger"],
    "Fashion": ["Jacket", "Sneakers", "Handbag", "Sunglasses", "Scarf", "Watch"],
    "Home": ["Lamp", "Cushion", "Coffee Maker", "Vase", "Blender", "Rug"],
    "Toys": ["Robot Kit", "Puzzle", "Plush Bear", "Race Car", "Building Blocks", "Drone"],
}


@st.cache_data
def generate_products(n_per_category: int = 8, seed: int = 42):
    rng = random.Random(seed)
    products = []
    pid = 1
    for cat in CATEGORIES:
        for i in range(1, n_per_category + 1):
            price = round(rng.uniform(15, 350), 2)
            discount = rng.choice([0, 0, 0, 10, 15, 20, 25, 30])
            products.append(
                {
                    "id": pid,
                    "name": f"{rng.choice(ADJECTIVES)} {rng.choice(NOUNS[cat])}",
                    "category": cat,
                    "price": price,
                    "discount": discount,
                    "final_price": round(price * (1 - discount / 100), 2),
                    "rating": round(rng.uniform(3.5, 5.0), 1),
                    "reviews": rng.randint(12, 2400),
                    "image": (
                        f"https://placehold.co/400x400/{CATEGORY_COLORS[cat]}/ffffff"
                        f"?text={cat}+{i}&font=raleway"
                    ),
                }
            )
            pid += 1
    return products


@st.cache_data
def generate_reviews(seed: int = 7):
    rng = random.Random(seed)
    names = ["Aisha K.", "Rahul M.", "Sofia L.", "Omar H.", "Emily R.", "Chen W."]
    texts = [
        "Fast delivery and the quality exceeded my expectations!",
        "ShopStream is now my go-to store. Great deals every day.",
        "Customer support was super helpful with my exchange.",
        "Loved the recommendations — found exactly what I needed.",
        "Beautiful packaging, great prices. Highly recommend!",
        "The Deal of the Day saved me a lot. Will shop again.",
    ]
    return [
        {"name": n, "text": t, "stars": rng.randint(4, 5), "city": rng.choice(
            ["Dubai", "Mumbai", "London", "Toronto", "Singapore", "Sydney"])}
        for n, t in zip(names, texts)
    ]


PRODUCTS = generate_products()
REVIEWS = generate_reviews()
BY_ID = {p["id"]: p for p in PRODUCTS}


# Extra styles for v2 (auth + cart pages)
st.markdown(
    """
<style>
.user-chip{color:var(--text); font-weight:600; margin-left:22px;}
.cart-row{display:flex; gap:14px; align-items:center; background:var(--card);
  border:1px solid var(--card-border); border-radius:12px; padding:10px;}
.cart-row img{width:72px; height:72px; border-radius:8px; object-fit:cover;}
.auth-box{background:var(--card); border:1px solid var(--card-border); border-radius:16px;
  padding:22px 26px;}
.summary-box{background:var(--card); border:1px solid var(--card-border); border-radius:16px;
  padding:18px 22px;}
.summary-box .line{display:flex; justify-content:space-between; color:#d1d5db; margin:6px 0;}
.summary-box .grand{font-size:1.3rem; font-weight:800; color:var(--text);
  border-top:1px solid var(--card-border); padding-top:10px; margin-top:10px;}
</style>
""",
    unsafe_allow_html=True,
)

db_init_db()

FREE_SHIPPING_OVER = 50.0
SHIPPING_FEE = 4.99


# ----------------------------------------------------------------------------
# Session state & authentication
# ----------------------------------------------------------------------------
st.session_state.setdefault("user", None)          # dict of the logged-in user, or None
st.session_state.setdefault("guest_cart", {})      # {product_id: {"qty": n, "price": p}}
st.session_state.setdefault("interests", set())
if "redirect" in st.session_state:  # page change requested after the menu was drawn last run
    st.session_state.nav = st.session_state.pop("redirect")
st.session_state.setdefault("nav", "🏠 Shop")   # current page (bound to the sidebar menu)

# Restore a login after a page reload: the session token lives in the URL (?session=…)
if st.session_state.user is None and st.query_params.get("session"):
    row = db_user_for_session(st.query_params["session"])
    if row:
        st.session_state.user = dict(row)
    else:  # expired or invalid token
        del st.query_params["session"]


def current_user():
    return st.session_state.user


def log_in(user_row):
    user = dict(db_get_user(user_row["id"]))
    st.session_state.user = user
    st.query_params["session"] = db_create_session(user["id"])
    # Merge anything the guest added before logging in into their saved cart
    for pid, item in st.session_state.guest_cart.items():
        db_add_to_cart(user["id"], pid, item["price"], item["qty"])
    st.session_state.guest_cart = {}


def log_out():
    token = st.query_params.get("session")
    if token:
        db_delete_session(token)
        del st.query_params["session"]
    st.session_state.user = None
    st.session_state.nav = "🏠 Shop"


# ----------------------------------------------------------------------------
# Cart service: SQLite for logged-in users, session memory for guests
# ----------------------------------------------------------------------------
def cart_items() -> list:
    """List of {product_id, quantity, unit_price} for the current visitor."""
    user = current_user()
    if user:
        return db_get_cart(user["id"])
    return [{"product_id": pid, "quantity": v["qty"], "unit_price": v["price"]}
            for pid, v in st.session_state.guest_cart.items()]


def add_to_cart(pid: int, price: float | None = None):
    product = BY_ID[pid]
    price = product["final_price"] if price is None else price
    user = current_user()
    if user:
        db_add_to_cart(user["id"], pid, price)
        st.toast(f"Added **{product['name']}** to your cart 🛒")
    else:
        item = st.session_state.guest_cart.setdefault(pid, {"qty": 0, "price": price})
        item["qty"] += 1
        item["price"] = min(item["price"], price)
        st.toast(f"Added **{product['name']}** — log in to save your cart 🛒")
    st.session_state.interests.add(product["category"])


def set_quantity(pid: int, qty: int):
    user = current_user()
    if user:
        db_set_quantity(user["id"], pid, qty)
    elif qty <= 0:
        st.session_state.guest_cart.pop(pid, None)
    else:
        st.session_state.guest_cart[pid]["qty"] = qty


def money(x: float) -> str:
    # &#36; instead of "$" so Streamlit's markdown doesn't treat $...$ as LaTeX
    return f"&#36;{x:,.2f}"


def stars(r: float) -> str:
    full = int(round(r))
    return "★" * full + "☆" * (5 - full)


# ----------------------------------------------------------------------------
# Reusable product card
# ----------------------------------------------------------------------------
def product_card(p: dict, key_prefix: str):
    if p["discount"]:
        price_html = (
            f'<span class="sale-badge">-{p["discount"]}%</span>'
            f'<span class="price">{money(p["final_price"])}</span>'
            f'<span class="old-price">{money(p["price"])}</span>'
        )
    else:
        price_html = f'<span class="price">{money(p["price"])}</span>'

    st.markdown(
        f"""
<div class="product-card">
  <img src="{p['image']}" alt="{p['name']}">
  <div class="product-cat">{CATEGORY_ICONS[p['category']]} {p['category']}</div>
  <div class="product-name">{p['name']}</div>
  <div class="price-row">{price_html}</div>
  <div class="rating">{stars(p['rating'])}<span>{p['rating']}/5 · {p['reviews']} reviews</span></div>
</div>
""",
        unsafe_allow_html=True,
    )
    st.button("Add to Cart 🛒", key=f"{key_prefix}_{p['id']}",
              on_click=add_to_cart, args=(p["id"],))


def product_grid(items: list, key_prefix: str, cols: int = 4):
    if not items:
        st.info("No products match your search.")
        return
    for row_start in range(0, len(items), cols):
        columns = st.columns(cols, gap="medium")
        for col, p in zip(columns, items[row_start:row_start + cols]):
            with col:
                product_card(p, key_prefix)


def go_to(page: str):
    st.session_state.nav = page  # only called from button callbacks, before the menu renders


# ----------------------------------------------------------------------------
# Sidebar: navigation, account status, filters
# ----------------------------------------------------------------------------
items_now = cart_items()
cart_count = sum(i["quantity"] for i in items_now)
PAGES = ["🏠 Shop", "🛒 Cart", "👤 Account"]

with st.sidebar:
    user = current_user()
    if user:
        st.markdown(f"### 👋 Hi, {user['full_name'].split()[0]}")
        st.caption(f"Signed in as @{user['username']}")
        st.button("Log out", on_click=log_out, use_container_width=True)
    else:
        st.markdown("### 👋 Welcome, guest")
        st.caption("Log in to save your cart across visits.")
        st.button("Log in / Sign up", on_click=go_to, args=("👤 Account",),
                  use_container_width=True, type="primary")
    st.divider()

    st.radio("Navigate", PAGES, key="nav", label_visibility="collapsed",
             format_func=lambda p: f"{p} ({cart_count})" if p == "🛒 Cart" and cart_count else p)

    if st.session_state.nav == "🏠 Shop":
        st.divider()
        st.markdown("## 🔎 Filters")
        price_range = st.slider("Price range ($)", 0, 400, (0, 400), step=10)
        min_rating = st.slider("Minimum rating", 3.5, 5.0, 3.5, step=0.1)
        sort_by = st.selectbox("Sort by", ["Featured", "Price: Low → High",
                                           "Price: High → Low", "Top Rated", "Biggest Discount"])


def apply_filters(items):
    items = [p for p in items
             if price_range[0] <= p["final_price"] <= price_range[1]
             and p["rating"] >= min_rating]
    if sort_by == "Price: Low → High":
        items.sort(key=lambda p: p["final_price"])
    elif sort_by == "Price: High → Low":
        items.sort(key=lambda p: -p["final_price"])
    elif sort_by == "Top Rated":
        items.sort(key=lambda p: -p["rating"])
    elif sort_by == "Biggest Discount":
        items.sort(key=lambda p: -p["discount"])
    return items


# ----------------------------------------------------------------------------
# Navbar (shown on every page)
# ----------------------------------------------------------------------------
user = current_user()
user_html = (f'<span class="user-chip">👤 {user["username"]}</span>' if user
             else '<span class="user-chip">👤 Guest</span>')
st.markdown(
    f"""
<div class="navbar">
  <div class="brand">🛍️ Shop<span>Stream</span></div>
  <div class="nav-links">
    <a href="#featured-products">Featured</a>
    <a href="#deal-of-the-day">Deals</a>
    <a href="#shop-by-category">Categories</a>
    <a href="#what-our-customers-say">Reviews</a>
    {user_html}
    <span class="cart-pill">🛒 {cart_count}</span>
  </div>
</div>
""",
    unsafe_allow_html=True,
)


# ============================================================================
# PAGE: Account (login / signup / profile / orders)
# ============================================================================
def account_page():
    user = current_user()
    if not user:
        st.markdown('<div class="section-title">👤 Your Account</div>', unsafe_allow_html=True)
        _, mid, _ = st.columns([1, 2, 1])
        with mid:
            tab_login, tab_signup = st.tabs(["🔐 Log in", "✨ Sign up"])
            with tab_login:
                with st.form("login_form"):
                    login = st.text_input("Username or email")
                    pw = st.text_input("Password", type="password")
                    if st.form_submit_button("Log in", type="primary", use_container_width=True):
                        row = db_authenticate(login, pw)
                        if row:
                            log_in(row)
                            st.session_state.redirect = "🏠 Shop"
                            st.rerun()
                        else:
                            st.error("Incorrect username/email or password.")
            with tab_signup:
                with st.form("signup_form"):
                    full_name = st.text_input("Full name")
                    username = st.text_input("Username")
                    email = st.text_input("Email")
                    pw1 = st.text_input("Password (min. 8 characters)", type="password")
                    pw2 = st.text_input("Confirm password", type="password")
                    if st.form_submit_button("Create account", type="primary",
                                             use_container_width=True):
                        if pw1 != pw2:
                            st.error("Passwords don't match.")
                        else:
                            uid, err = db_create_user(username, email, full_name, pw1)
                            if err:
                                st.error(err)
                            else:
                                log_in({"id": uid})
                                st.session_state.redirect = "🏠 Shop"
                                st.rerun()
            if st.session_state.guest_cart:
                st.info("Items in your guest cart will be saved to your account when you log in.")
        return

    st.markdown(f'<div class="section-title">👤 {user["full_name"]}</div>', unsafe_allow_html=True)
    m1, m2, m3 = st.columns(3)
    orders = db_get_orders(user["id"])
    m1.metric("Member since", user["created_at"][:10])
    m2.metric("Orders placed", len(orders))
    m3.metric("Items in cart", cart_count)

    t_profile, t_orders, t_security = st.tabs(["📝 Profile", "📦 Order history", "🔒 Security"])
    with t_profile:
        with st.form("profile_form"):
            st.text_input("Username", value=user["username"], disabled=True)
            name = st.text_input("Full name", value=user["full_name"])
            email = st.text_input("Email", value=user["email"])
            if st.form_submit_button("Save changes"):
                err = db_update_profile(user["id"], name, email)
                if err:
                    st.error(err)
                else:
                    st.session_state.user = dict(db_get_user(user["id"]))
                    st.success("Profile updated.")
    with t_orders:
        if not orders:
            st.caption("No orders yet — your checkouts will appear here.")
        for o in orders:
            with st.expander(f"Order #{o['id']} · {o['created_at'][:16]} · ${o['total']:,.2f}"):
                for it in o["items"]:
                    p = BY_ID.get(it["product_id"], {"name": f"Product {it['product_id']}"})
                    st.markdown(f"- {p['name']} × {it['quantity']} — "
                                f"{money(it['unit_price'] * it['quantity'])}",
                                unsafe_allow_html=True)
    with t_security:
        with st.form("pw_form", clear_on_submit=True):
            cur = st.text_input("Current password", type="password")
            new1 = st.text_input("New password", type="password")
            new2 = st.text_input("Confirm new password", type="password")
            if st.form_submit_button("Change password"):
                if new1 != new2:
                    st.error("New passwords don't match.")
                else:
                    err = db_change_password(user["id"], cur, new1)
                    if err:
                        st.error(err)
                    else:
                        # old sessions were revoked; issue a fresh one for this browser
                        st.query_params["session"] = db_create_session(user["id"])
                        st.success("Password changed. Other devices have been signed out.")


# ============================================================================
# PAGE: Cart
# ============================================================================
def cart_page():
    st.markdown('<div class="section-title">🛒 Your Cart</div>', unsafe_allow_html=True)
    if "flash" in st.session_state:
        st.success(st.session_state.pop("flash"))
        st.balloons()
    items = cart_items()
    user = current_user()
    if not user:
        st.warning("You're shopping as a guest — this cart will be lost if you close the page. "
                   "Log in to save it.")
    if not items:
        st.info("Your cart is empty. Head to the shop to find something you love!")
        st.button("Continue shopping", on_click=go_to, args=("🏠 Shop",))
        return

    left, right = st.columns([2, 1], gap="large")
    subtotal = 0.0
    with left:
        for it in items:
            p = BY_ID[it["product_id"]]
            line = it["unit_price"] * it["quantity"]
            subtotal += line
            c_info, c_qty, c_rm = st.columns([5, 2, 1])
            with c_info:
                st.markdown(
                    f"""<div class="cart-row"><img src="{p['image']}">
<div><div class="product-name" style="margin:0">{p['name']}</div>
<div class="product-cat">{p['category']} · {money(it['unit_price'])} each</div>
<div class="price">{money(line)}</div></div></div>""",
                    unsafe_allow_html=True)
            with c_qty:
                new_q = st.number_input("Qty", min_value=1, max_value=99, value=it["quantity"],
                                        key=f"qty_{it['product_id']}_{it['quantity']}")
                if new_q != it["quantity"]:
                    set_quantity(it["product_id"], int(new_q))
                    st.rerun()
            with c_rm:
                st.write("")
                st.button("🗑️", key=f"rm_{it['product_id']}", help="Remove",
                          on_click=set_quantity, args=(it["product_id"], 0))

    shipping = 0.0 if subtotal >= FREE_SHIPPING_OVER else SHIPPING_FEE
    total = subtotal + shipping
    with right:
        st.markdown(
            f"""<div class="summary-box">
<h3 style="margin-top:0">Order summary</h3>
<div class="line"><span>Items ({sum(i['quantity'] for i in items)})</span><span>{money(subtotal)}</span></div>
<div class="line"><span>Shipping</span><span>{'FREE' if shipping == 0 else money(shipping)}</span></div>
<div class="line grand"><span>Total</span><span>{money(total)}</span></div>
</div>""",
            unsafe_allow_html=True)
        if shipping:
            st.caption(f"Add ${FREE_SHIPPING_OVER - subtotal:,.2f} more for free shipping.")
        st.write("")
        if user:
            if st.button("Place order (demo)", type="primary", use_container_width=True):
                order_id, _ = db_place_order(user["id"])
                st.session_state.flash = (f"Order #{order_id} placed! No payment was taken — this "
                                          "is a demo. You'll find it under Account → Order history.")
                st.rerun()  # redraw so the cart count everywhere drops to 0
            if st.button("Empty cart", use_container_width=True):
                db_clear_cart(user["id"])
                st.rerun()
        else:
            st.button("Log in to check out", type="primary", use_container_width=True,
                      on_click=go_to, args=("👤 Account",))


# ============================================================================
# PAGE: Shop (the Part I homepage)
# ============================================================================
def shop_page():
    search = st.text_input("Search", placeholder="🔍  Search products, e.g. 'headphones' or 'toys'…",
                           label_visibility="collapsed")
    if search.strip():
        q = search.strip().lower()
        results = [p for p in PRODUCTS if q in p["name"].lower() or q in p["category"].lower()]
        for p in results:
            st.session_state.interests.add(p["category"])
        st.markdown(f'<div class="section-title">Search results for "{search}"</div>',
                    unsafe_allow_html=True)
        product_grid(apply_filters(results), "search")

    user = current_user()
    greeting = f"Welcome back, {user['full_name'].split()[0]}!" if user else "Shop Smarter. Live Better."
    st.markdown(
        f"""
<div class="hero">
  <div class="badge">🔥 MEGA SALE · Limited time</div>
  <h1>{greeting}</h1>
  <p>Up to 30% off across Electronics, Fashion, Home &amp; Toys. Free shipping on orders over &#36;50.</p>
  <span class="cta">Start Shopping →</span>
</div>
""",
        unsafe_allow_html=True,
    )

    # Featured products — one from each category, stable for the day
    st.markdown('<div class="section-title" id="featured-products">⭐ Featured Products</div>',
                unsafe_allow_html=True)
    day_rng = random.Random(date.today().toordinal())
    featured = [day_rng.choice([p for p in PRODUCTS if p["category"] == c]) for c in CATEGORIES]
    product_grid(featured, "featured")

    # Deal of the day
    st.markdown('<div class="section-title" id="deal-of-the-day">⚡ Deal of the Day</div>',
                unsafe_allow_html=True)
    deal = day_rng.choice(PRODUCTS)
    deal_price = round(deal["price"] * 0.6, 2)
    d1, d2 = st.columns([3, 1])
    with d1:
        st.markdown(
            f"""
<div class="deal">
  <img src="{deal['image']}" alt="{deal['name']}">
  <div>
    <span class="sale-badge">40% OFF TODAY</span>
    <h2>{deal['name']}</h2>
    <div class="product-cat" style="color:#c7d2fe">{deal['category']}</div>
    <div class="big-price">{money(deal_price)}
      <span class="old-price" style="font-size:1.1rem">{money(deal['price'])}</span></div>
    <div class="rating">{stars(deal['rating'])}<span style="color:#c7d2fe">{deal['rating']}/5</span></div>
    <div class="timer">⏰ Ends at midnight</div>
  </div>
</div>
""",
            unsafe_allow_html=True,
        )
    with d2:
        st.write("")
        st.metric("You save", f"${deal['price'] - deal_price:,.2f}", "-40%")
        # The deal price is stored with the cart item, so it survives reloads
        st.button("Grab the Deal 🛒", key="deal_btn", type="primary",
                  on_click=add_to_cart, args=(deal["id"], deal_price))

    # Catalogue by category
    st.markdown('<div class="section-title" id="shop-by-category">🗂️ Shop by Category</div>',
                unsafe_allow_html=True)
    tabs = st.tabs([f"{CATEGORY_ICONS[c]} {c}" for c in CATEGORIES])
    for tab, cat in zip(tabs, CATEGORIES):
        with tab:
            product_grid(apply_filters([p for p in PRODUCTS if p["category"] == cat]), f"cat_{cat}")

    # Recommendations — from chosen interests plus categories already in the saved cart
    st.markdown('<div class="section-title">🎯 Recommended for You</div>', unsafe_allow_html=True)
    in_cart = {i["product_id"] for i in cart_items()}
    cart_cats = {BY_ID[pid]["category"] for pid in in_cart}
    chosen = st.multiselect("What are you interested in?", CATEGORIES,
                            default=sorted(st.session_state.interests | cart_cats))
    interest = set(chosen) or set(CATEGORIES)
    if chosen:
        st.caption(f"Based on your interest in {', '.join(chosen)}.")
    else:
        st.caption("Pick a category or add items to your cart to personalise these. "
                   "Showing top-rated picks.")
    pool = [p for p in PRODUCTS if p["category"] in interest and p["id"] not in in_cart]
    recs = sorted(pool, key=lambda p: (-p["rating"], -p["discount"]))[:4]
    product_grid(recs, "rec")

    # Featured video
    st.markdown('<div class="section-title">🎬 Featured Video</div>', unsafe_allow_html=True)
    v1, v2 = st.columns([2, 1])
    with v1:
        st.video("https://www.youtube.com/watch?v=aqz-KE-bpKQ")  # placeholder promo (CC-BY)
    with v2:
        st.markdown("### The ShopStream Season Launch")
        st.write("Get a first look at this season's collections, curated by our style and tech "
                 "teams. New arrivals drop every Friday.")
        st.markdown("- 🚚 Free shipping over &#36;50\n- ↩️ 30-day easy returns\n- 🔒 Secure checkout",
                    unsafe_allow_html=True)

    # Reviews
    st.markdown('<div class="section-title" id="what-our-customers-say">💬 What Our Customers Say</div>',
                unsafe_allow_html=True)
    for row in range(0, len(REVIEWS), 3):
        cols = st.columns(3, gap="medium")
        for col, r in zip(cols, REVIEWS[row:row + 3]):
            col.markdown(
                f"""
<div class="review">
  <div class="rating">{stars(r['stars'])}</div>
  <div class="text">“{r['text']}”</div>
  <div class="who">{r['name']}</div>
  <div class="meta">Verified buyer · {r['city']}</div>
</div>
""",
                unsafe_allow_html=True,
            )
        st.write("")

    # Newsletter — subscribers are now saved in SQLite
    st.markdown(
        """
<div class="newsletter">
  <h3>📬 Join the ShopStream newsletter</h3>
  <div>Exclusive deals, early access to sales and new arrivals — straight to your inbox.</div>
</div>
""",
        unsafe_allow_html=True,
    )
    with st.form("newsletter", clear_on_submit=True):
        n1, n2 = st.columns([4, 1])
        email = n1.text_input("Email", placeholder="you@example.com",
                              value=user["email"] if user else "", label_visibility="collapsed")
        if n2.form_submit_button("Subscribe"):
            result = db_subscribe(email or "")
            if result == "ok":
                st.success(f"Thanks! {email} is now subscribed. 🎉")
            elif result == "exists":
                st.info("You're already subscribed! 💌")
            else:
                st.error("Please enter a valid email address.")


# ----------------------------------------------------------------------------
# Router
# ----------------------------------------------------------------------------
page = st.session_state.nav
if page == "🛒 Cart":
    cart_page()
elif page == "👤 Account":
    account_page()
else:
    shop_page()

st.markdown(
    '<div class="footer">© 2026 ShopStream · Demo store with simulated data · Built with Streamlit</div>',
    unsafe_allow_html=True,
)
