# ShopStream v2: login and persistent cart

## Run
```bash
pip install -r requirements.txt
streamlit run app.py
```
The first time the app runs, it creates the `shopstream.db` SQLite file automatically.

## Files
| File | Purpose |
|---|---|
| `app.py` | The Streamlit UI: the Part I shop, plus the Cart and Account pages |
| `db.py` | All the SQLite code: users, login sessions, cart, orders, newsletter |

## Database tables
- **users**: username, email, full name, and a hashed password with its salt (PBKDF2-SHA256; passwords are never stored in plain text)
- **sessions**: random login tokens that expire after 7 days, so a reload keeps you signed in
- **cart_items**: one row per user and product, with quantity and the price when added
- **orders / order_items**: created by the demo checkout and shown in the order history
- **subscribers**: newsletter emails

## How it fits together
- Guests can browse and add to a temporary cart. When they log in or sign up, that cart is merged into their saved cart.
- Logged-in users' carts are read from and written to SQLite, so they survive reloads and later visits.
- The Deal-of-the-Day price is saved with the cart item, so the discount isn't lost.
- To start fresh, delete `shopstream.db`.

## Possible next steps
Add payment processing (e.g. Stripe), product data in a database table, advanced filtering, and an admin panel.
