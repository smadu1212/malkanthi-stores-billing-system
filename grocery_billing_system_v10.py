import csv
import os
import hashlib
import hmac
import secrets
import math
import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path
from datetime import datetime, timedelta
from contextlib import closing
from xml.sax.saxutils import escape as xml_escape
import webbrowser

import sys

if getattr(sys, "frozen", False):
    BASE = Path(sys.executable).resolve().parent
else:
    BASE = Path(__file__).resolve().parent
DB = BASE / 'grocery.db'
RECEIPTS = BASE / 'receipts'
PRINT_DIR = BASE / 'print_jobs'
BACKUPS = BASE / 'backups'

def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 250_000)
    return salt.hex() + ':' + hashed.hex()

def verify_password(password, stored):
    try:
        salt_hex, expected = stored.split(':', 1)
        candidate = hash_password(password, bytes.fromhex(salt_hex)).split(':', 1)[1]
        return hmac.compare_digest(candidate, expected)
    except (ValueError, TypeError):
        return False


def rupees(x):
    return f'Rs. {x:,.2f}'

def connection():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys=ON')
    return con

with connection() as con:
    con.executescript('''
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'cashier');
    CREATE TABLE IF NOT EXISTS settings(
      key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS products(
      id INTEGER PRIMARY KEY, barcode TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL, price REAL NOT NULL CHECK(price>=0),
      cost REAL NOT NULL DEFAULT 0 CHECK(cost>=0),
      stock REAL NOT NULL CHECK(stock>=0), unit TEXT NOT NULL DEFAULT 'pcs');
    CREATE TABLE IF NOT EXISTS sales(
      id INTEGER PRIMARY KEY, created TEXT NOT NULL, subtotal REAL NOT NULL,
      discount REAL NOT NULL, total REAL NOT NULL);
    CREATE TABLE IF NOT EXISTS sale_items(
      id INTEGER PRIMARY KEY, sale_id INTEGER NOT NULL REFERENCES sales(id),
      product_id INTEGER, barcode TEXT, name TEXT NOT NULL,
      qty REAL NOT NULL, price REAL NOT NULL, cost REAL NOT NULL, total REAL NOT NULL);
    ''')
    # Additive migration: preserve all Version 4 records and user accounts.
    existing = {r[1] for r in con.execute('PRAGMA table_info(sales)')}
    for col, spec in [('cashier', "TEXT NOT NULL DEFAULT ''"), ('payment_method', "TEXT NOT NULL DEFAULT 'Cash'"), ('paid', 'REAL'), ('change_due', 'REAL')]:
        if col not in existing:
            con.execute(f'ALTER TABLE sales ADD COLUMN {col} {spec}')

    con.executescript("""
    CREATE TABLE IF NOT EXISTS returns (
      id INTEGER PRIMARY KEY, sale_item_id INTEGER NOT NULL REFERENCES sale_items(id),
      sale_id INTEGER NOT NULL REFERENCES sales(id), created TEXT NOT NULL,
      qty REAL NOT NULL CHECK(qty>0), refund REAL NOT NULL CHECK(refund>=0),
      cost REAL NOT NULL CHECK(cost>=0), cashier TEXT NOT NULL, reason TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS expenses (
      id INTEGER PRIMARY KEY, created TEXT NOT NULL, category TEXT NOT NULL,
      description TEXT NOT NULL, amount REAL NOT NULL CHECK(amount>0), cashier TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS purchases (
      id INTEGER PRIMARY KEY, created TEXT NOT NULL, product_id INTEGER NOT NULL REFERENCES products(id),
      qty REAL NOT NULL CHECK(qty>0), unit_cost REAL NOT NULL CHECK(unit_cost>=0),
      supplier TEXT NOT NULL, cashier TEXT NOT NULL);
    """)

# V8 additive migration. Existing sales, users and stock remain untouched.
with connection() as con:
    cols = {r[1] for r in con.execute('PRAGMA table_info(products)')}
    if 'min_stock' not in cols:
        con.execute('ALTER TABLE products ADD COLUMN min_stock REAL NOT NULL DEFAULT 5')
    cols = {r[1] for r in con.execute('PRAGMA table_info(sales)')}
    if 'customer_id' not in cols:
        con.execute('ALTER TABLE sales ADD COLUMN customer_id INTEGER')
    con.executescript("""
    CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY, name TEXT NOT NULL, phone TEXT NOT NULL DEFAULT '',
        address TEXT NOT NULL DEFAULT '', created TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS credit_payments (
        id INTEGER PRIMARY KEY, sale_id INTEGER NOT NULL REFERENCES sales(id),
        customer_id INTEGER NOT NULL REFERENCES customers(id),
        amount REAL NOT NULL CHECK(amount>0), created TEXT NOT NULL,
        cashier TEXT NOT NULL, note TEXT NOT NULL DEFAULT '');
    CREATE INDEX IF NOT EXISTS idx_sales_customer ON sales(customer_id);
    CREATE INDEX IF NOT EXISTS idx_credit_payments_sale ON credit_payments(sale_id);
    """)

def finite_number(raw, label, minimum=0, positive=False):
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise ValueError(label + ' must be a number.')
    if not math.isfinite(value) or value < minimum or (positive and value <= 0):
        raise ValueError(label + ' must be a valid positive amount.')
    return value

def automatic_backup():
    """Create a daily SQLite snapshot directly (no Windows-sensitive temp rename)."""
    BACKUPS.mkdir(exist_ok=True)
    today = datetime.now().strftime('%Y%m%d')
    target = BACKUPS / ('grocery_auto_' + today + '.db')
    if target.exists():
        # Do not overwrite or remove an existing backup automatically.
        with closing(sqlite3.connect(f'file:{target.as_posix()}?mode=ro', uri=True)) as check:
            if check.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise RuntimeError('Existing daily backup failed integrity check: ' + str(target))
    else:
        try:
            with closing(connection()) as source:
                with closing(sqlite3.connect(str(target))) as dest:
                    source.backup(dest)
            with closing(sqlite3.connect(f'file:{target.as_posix()}?mode=ro', uri=True)) as check:
                if check.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                    raise RuntimeError('New backup failed integrity check: ' + str(target))
        except Exception:
            # A failed backup may be incomplete. Do not silently count it as valid.
            # Leave it for inspection rather than risking a deletion of user files.
            raise
    for old in sorted(BACKUPS.glob('grocery_auto_????????.db'), reverse=True)[14:]:
        try:
            old.unlink()
        except OSError:
            pass

def login_or_setup(root):
    with connection() as con:
        count = con.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    first = count == 0
    dialog = tk.Toplevel(root)
    dialog.title('Create Admin Account' if first else 'Grocery Shop Login')
    dialog.geometry('390x290' if first else '390x245')
    dialog.resizable(False, False)
    dialog.grab_set()
    ttk.Label(dialog, text='First-time admin setup' if first else 'Staff Login',
              font=('Segoe UI', 17, 'bold')).pack(pady=(16, 10))
    ttk.Label(dialog, text='Username').pack(anchor='w', padx=35)
    user_var = tk.StringVar(value='admin' if first else '')
    user_entry = ttk.Entry(dialog, textvariable=user_var, width=34)
    user_entry.pack(padx=35, fill='x')
    ttk.Label(dialog, text='Password').pack(anchor='w', padx=35, pady=(8, 0))
    pass_var = tk.StringVar()
    pass_entry = ttk.Entry(dialog, textvariable=pass_var, show='*')
    pass_entry.pack(padx=35, fill='x')
    confirm_var = tk.StringVar()
    if first:
        ttk.Label(dialog, text='Confirm password (at least 8 characters)').pack(anchor='w', padx=35, pady=(8, 0))
        ttk.Entry(dialog, textvariable=confirm_var, show='*').pack(padx=35, fill='x')
    result = {'user': None}
    def submit(event=None):
        username, password = user_var.get().strip(), pass_var.get()
        if not username or not password:
            messagebox.showerror('Login', 'Enter username and password.', parent=dialog)
            return
        if first:
            if len(password) < 8 or password != confirm_var.get():
                messagebox.showerror('Setup', 'Use at least 8 characters and matching passwords.', parent=dialog)
                return
            try:
                with connection() as con:
                    con.execute('INSERT INTO users(username,password_hash,role) VALUES (?,?,?)',
                                (username, hash_password(password), 'admin'))
            except sqlite3.IntegrityError:
                messagebox.showerror('Setup', 'Username already exists.', parent=dialog)
                return
            result['user'] = {'username': username, 'role': 'admin'}
        else:
            with connection() as con:
                row = con.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
            if not row or not verify_password(password, row['password_hash']):
                messagebox.showerror('Login', 'Incorrect username or password.', parent=dialog)
                return
            result['user'] = {'username': row['username'], 'role': row['role']}
        dialog.destroy()
    ttk.Button(dialog, text='Create Admin' if first else 'Login', command=submit).pack(pady=16)
    dialog.bind('<Return>', submit)
    dialog.protocol('WM_DELETE_WINDOW', dialog.destroy)
    user_entry.focus_set()
    root.wait_window(dialog)
    return result['user']


# Version 9 additive schema migration: no old tables or records are removed.
with connection() as con:
    con.executescript("""
    CREATE TABLE IF NOT EXISTS suppliers_v9 (
        id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE,
        phone TEXT NOT NULL DEFAULT '', address TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '');
    CREATE TABLE IF NOT EXISTS expiry_batches_v9 (
        id INTEGER PRIMARY KEY, product_id INTEGER NOT NULL REFERENCES products(id),
        batch_code TEXT NOT NULL, expiry_date TEXT NOT NULL,
        qty REAL NOT NULL CHECK(qty>=0), created TEXT NOT NULL,
        UNIQUE(product_id,batch_code,expiry_date));
    CREATE TABLE IF NOT EXISTS cash_register_v9 (
        day TEXT PRIMARY KEY, opening REAL NOT NULL CHECK(opening>=0),
        counted REAL, closed_at TEXT, cashier TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS cash_movements_v9 (
        id INTEGER PRIMARY KEY, day TEXT NOT NULL, amount REAL NOT NULL,
        description TEXT NOT NULL, cashier TEXT NOT NULL, created TEXT NOT NULL);
    """)
    cols={r[1] for r in con.execute('PRAGMA table_info(purchases)')}
    if 'supplier_id_v9' not in cols:
        con.execute('ALTER TABLE purchases ADD COLUMN supplier_id_v9 INTEGER')

# Version 10 additive schema: never drop or overwrite previous data.
with connection() as con:
    con.executescript("""
    CREATE TABLE IF NOT EXISTS purchase_orders_v10(id INTEGER PRIMARY KEY,created TEXT NOT NULL,supplier_id INTEGER NOT NULL REFERENCES suppliers_v9(id),product_id INTEGER NOT NULL REFERENCES products(id),qty REAL NOT NULL CHECK(qty>0),unit_cost REAL NOT NULL CHECK(unit_cost>=0),status TEXT NOT NULL DEFAULT 'ORDERED',cashier TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS stock_adjustments_v10(id INTEGER PRIMARY KEY,created TEXT NOT NULL,product_id INTEGER NOT NULL REFERENCES products(id),delta REAL NOT NULL,before_qty REAL NOT NULL,after_qty REAL NOT NULL,reason TEXT NOT NULL,cashier TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS cashier_shifts_v10(id INTEGER PRIMARY KEY,cashier TEXT NOT NULL,started TEXT NOT NULL,ended TEXT,opening REAL NOT NULL CHECK(opening>=0),cash_sales REAL,counted REAL);
    CREATE TABLE IF NOT EXISTS product_categories_v10(id INTEGER PRIMARY KEY,name TEXT NOT NULL UNIQUE);
    """)
    if 'category_id_v10' not in {r[1] for r in con.execute('PRAGMA table_info(products)')}:
        con.execute('ALTER TABLE products ADD COLUMN category_id_v10 INTEGER REFERENCES product_categories_v10(id)')

class App:
    def __init__(self, root, user):
        self.user = user
        self.root = root
        root.title('MALKANTHI STORES Grocery Billing System V10 - LKR | ' + user['username'] + ' (' + user['role'] + ')')
        root.geometry('1120x720')
        self.cart = {}
        self.last_receipt = ''
        topbar = ttk.Frame(root, padding=(12, 8))
        topbar.pack(fill='x')
        ttk.Label(topbar, text='Signed in: ' + user['username'] + ' (' + user['role'] + ')').pack(side='left')
        ttk.Button(topbar, text='Logout', command=self.logout).pack(side='right')
        tabs = ttk.Notebook(root)
        tabs.pack(fill='both', expand=True, padx=12, pady=12)
        self.bill = ttk.Frame(tabs, padding=12)
        self.products = ttk.Frame(tabs, padding=12)
        self.history = ttk.Frame(tabs, padding=12)
        self.dashboard = ttk.Frame(tabs, padding=12)
        self.settings_tab = ttk.Frame(tabs, padding=12)
        tabs.add(self.bill, text='Billing')
        tabs.add(self.products, text='Products / Stock')
        tabs.add(self.history, text='Sales / Reports')
        self.returns_tab = ttk.Frame(tabs, padding=12)
        self.expenses_tab = ttk.Frame(tabs, padding=12)
        self.purchases_tab = ttk.Frame(tabs, padding=12)
        self.advanced_tab = ttk.Frame(tabs, padding=12)
        self.customers_tab = ttk.Frame(tabs, padding=12)
        self.credit_tab = ttk.Frame(tabs, padding=12)
        self.labels_tab = ttk.Frame(tabs, padding=12)
        tabs.add(self.dashboard, text='Dashboard')
        tabs.add(self.returns_tab, text='Returns')
        tabs.add(self.expenses_tab, text='Expenses')
        tabs.add(self.purchases_tab, text='Stock Purchases')
        tabs.add(self.advanced_tab, text='Advanced Reports')
        tabs.add(self.customers_tab, text='Customers')
        tabs.add(self.credit_tab, text='Credit Book')
        tabs.add(self.labels_tab, text='Barcode Labels')
        self.suppliers_tab = ttk.Frame(tabs, padding=12)
        self.expiry_tab = ttk.Frame(tabs, padding=12)
        self.cash_tab = ttk.Frame(tabs, padding=12)
        self.v9_dashboard_tab = ttk.Frame(tabs, padding=12)
        self.restore_tab = ttk.Frame(tabs, padding=12)
        tabs.add(self.suppliers_tab, text='Suppliers V9')
        tabs.add(self.expiry_tab, text='Expiry Alerts V9')
        tabs.add(self.cash_tab, text='Daily Cash V9')
        tabs.add(self.v9_dashboard_tab, text='Profit Dashboard V9')
        tabs.add(self.restore_tab, text='Backup Restore V9')
        self.orders_tab_v10=ttk.Frame(tabs,padding=12)
        self.adjust_tab_v10=ttk.Frame(tabs,padding=12)
        self.statement_tab_v10=ttk.Frame(tabs,padding=12)
        self.shift_tab_v10=ttk.Frame(tabs,padding=12)
        self.category_tab_v10=ttk.Frame(tabs,padding=12)
        self.business_tab_v10=ttk.Frame(tabs,padding=12)
        for tab,label in [(self.orders_tab_v10,'Purchase Orders V10'),(self.adjust_tab_v10,'Stock Adjustments V10'),(self.statement_tab_v10,'Customer Statements V10'),(self.shift_tab_v10,'Cashier Shifts V10'),(self.category_tab_v10,'Categories V10'),(self.business_tab_v10,'Business Reports V10')]:
            tabs.add(tab,text=label)
        tabs.add(self.settings_tab, text='Settings / Staff')
        self.make_bill()
        self.make_products()
        self.make_history()
        self.make_dashboard()
        self.make_settings()
        self.make_returns()
        self.make_expenses()
        self.make_purchases()
        self.make_advanced()
        ttk.Button(self.advanced_tab,text='Export Excel Workbook (.xlsx)',command=self.export_excel).pack(anchor='w',pady=3)
        self.make_customers()
        self.make_credit()
        self.make_labels()
        self.make_suppliers_v9()
        self.make_expiry_v9()
        self.make_cash_v9()
        self.make_profit_v9()
        self.make_restore_v9()
        self.make_orders_v10()
        self.make_adjustments_v10()
        self.make_statements_v10()
        self.make_shifts_v10()
        self.make_categories_v10()
        self.make_business_reports_v10()
        self.refresh_products()
        self.refresh_history()
        self.refresh_dashboard()
        self.refresh_advanced()
        if user['role'] != 'admin':
            for button in (self.product_add_button, self.product_update_button, self.product_delete_button):
                button.state(['disabled'])
        tabs.bind('<<NotebookTabChanged>>', lambda e: self.on_tab_changed(tabs))
        self.scan.focus_set()

    def on_tab_changed(self, tabs):
        selected=tabs.select()
        if selected==str(self.dashboard): self.refresh_dashboard()
        elif selected==str(self.advanced_tab): self.refresh_advanced()
        elif selected==str(self.expenses_tab): self.refresh_expenses()
        elif selected==str(self.purchases_tab): self.refresh_purchases()
        elif selected==str(self.customers_tab): self.refresh_customers()
        elif selected==str(self.credit_tab): self.refresh_credit()
        elif selected==str(self.suppliers_tab): self.refresh_suppliers_v9()
        elif selected==str(self.expiry_tab): self.refresh_expiry_v9()
        elif selected==str(self.cash_tab): self.refresh_cash_v9()
        elif selected==str(self.v9_dashboard_tab): self.refresh_profit_v9()
        elif selected==str(self.orders_tab_v10): self.refresh_orders_v10()
        elif selected==str(self.adjust_tab_v10): self.refresh_adjustments_v10()
        elif selected==str(self.shift_tab_v10): self.refresh_shifts_v10()
        elif selected==str(self.category_tab_v10): self.refresh_categories_v10()
        elif selected==str(self.business_tab_v10): self.refresh_business_v10()

    def tree(self, parent, columns, widths):
        frame = ttk.Frame(parent)
        frame.pack(fill='both', expand=True, pady=8)
        tree = ttk.Treeview(frame, columns=columns, show='headings')
        for col, width in zip(columns, widths):
            tree.heading(col, text=col.title())
            tree.column(col, width=width, anchor='w')
        scroll = ttk.Scrollbar(frame, orient='vertical', command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side='left', fill='both', expand=True)
        scroll.pack(side='right', fill='y')
        return tree

    def make_bill(self):
        top = ttk.Frame(self.bill)
        top.pack(fill='x')
        ttk.Label(top, text='Scan barcode or enter product name:').pack(side='left')
        self.scan_var = tk.StringVar()
        self.scan = ttk.Entry(top, textvariable=self.scan_var, width=35, font=('Segoe UI', 12))
        self.scan.pack(side='left', padx=8)
        self.scan.bind('<Return>', lambda e: self.add_to_cart())
        ttk.Button(top, text='Add', command=self.add_to_cart).pack(side='left')
        ttk.Label(top, text='Quantity (kg or pcs):').pack(side='left', padx=(18, 4))
        self.qty = tk.StringVar(value='1')
        ttk.Entry(top, textvariable=self.qty, width=8).pack(side='left')
        self.cart_tree = self.tree(self.bill, ('barcode','name','qty','unit','price','total'), (150,300,90,75,110,120))
        foot = ttk.Frame(self.bill)
        foot.pack(fill='x')
        ttk.Button(foot, text='Remove selected', command=self.remove_item).pack(side='left')
        ttk.Button(foot, text='Clear bill', command=self.clear_bill).pack(side='left', padx=8)
        ttk.Label(foot, text='Discount (Rs.):').pack(side='left', padx=(20, 5))
        self.discount = tk.StringVar(value='0')
        disc = ttk.Entry(foot, textvariable=self.discount, width=12)
        disc.pack(side='left')
        self.discount.trace_add('write', lambda *_: self.refresh_cart())
        self.total_label = ttk.Label(foot, text='Total: Rs. 0.00', font=('Segoe UI', 16, 'bold'))
        self.total_label.pack(side='right')
        payment = ttk.Frame(self.bill)
        payment.pack(fill='x', pady=(10, 0))
        ttk.Label(payment, text='Payment:').pack(side='left')
        self.payment_method = tk.StringVar(value='Cash')
        ttk.Combobox(payment, textvariable=self.payment_method, values=('Cash', 'Card', 'Bank Transfer', 'Credit'), state='readonly', width=16).pack(side='left', padx=8)
        ttk.Label(payment, text='Cash received (Rs.):').pack(side='left', padx=(16, 4))
        self.cash_received = tk.StringVar()
        ttk.Entry(payment, textvariable=self.cash_received, width=14).pack(side='left')
        ttk.Label(payment, text='(leave blank for exact cash)').pack(side='left', padx=8)
        self.balance_label = ttk.Label(self.bill, text='Balance: Rs. 0.00', font=('Segoe UI', 14, 'bold'))
        self.balance_label.pack(anchor='e', pady=(8, 0))
        self.cash_received.trace_add('write', lambda *_: self.update_balance())
        self.payment_method.trace_add('write', lambda *_: self.update_balance())
        customerline = ttk.Frame(self.bill)
        customerline.pack(fill='x', pady=4)
        ttk.Label(customerline, text='Customer for Credit:').pack(side='left')
        self.sale_customer = tk.StringVar()
        self.customer_combo = ttk.Combobox(customerline, textvariable=self.sale_customer, width=42, state='readonly')
        self.customer_combo.pack(side='left', padx=8)
        ttk.Button(customerline, text='Refresh customers', command=self.refresh_customer_combo).pack(side='left')
        self.refresh_customer_combo()
        self.update_balance()
        ttk.Button(self.bill, text='COMPLETE SALE & SAVE RECEIPT', command=self.complete_sale).pack(fill='x', pady=15)
        receipt_buttons = ttk.Frame(self.bill)
        receipt_buttons.pack(fill='x')
        ttk.Button(receipt_buttons, text='View last receipt', command=self.view_last).pack(side='right')
        ttk.Button(receipt_buttons, text='Print last receipt (Windows)', command=self.print_last).pack(side='right', padx=8)

    def make_products(self):
        form = ttk.LabelFrame(self.products, text='Product details', padding=10)
        form.pack(fill='x')
        self.pvars = {}
        for i, (key, label, default) in enumerate([
            ('barcode','Barcode',''), ('name','Product name',''),
            ('price','Selling price (Rs.)',''), ('cost','Cost price (Rs.)','0'),
            ('stock','Stock','0'), ('unit','Unit (pcs / kg)','pcs')]):
            cell = ttk.Frame(form)
            cell.grid(row=i//3, column=i%3, padx=8, pady=6, sticky='ew')
            ttk.Label(cell, text=label).pack(anchor='w')
            var = tk.StringVar(value=default)
            ttk.Entry(cell, textvariable=var, width=28).pack()
            self.pvars[key] = var
        buttons = ttk.Frame(self.products)
        buttons.pack(fill='x', pady=7)
        self.product_add_button = ttk.Button(buttons, text='Add product', command=self.save_product)
        self.product_add_button.pack(side='left')
        self.product_update_button = ttk.Button(buttons, text='Update selected', command=lambda: self.save_product(update=True))
        self.product_update_button.pack(side='left', padx=6)
        self.product_delete_button = ttk.Button(buttons, text='Delete selected', command=self.delete_product)
        self.product_delete_button.pack(side='left')
        ttk.Button(buttons, text='Set minimum stock', command=self.set_min_stock).pack(side='left', padx=6)
        ttk.Button(buttons, text='Clear form', command=self.clear_form).pack(side='left', padx=6)
        ttk.Button(buttons, text='Low stock report', command=self.low_stock_report).pack(side='left', padx=6)
        ttk.Button(buttons, text='Export stock CSV', command=self.export_stock_csv).pack(side='left', padx=6)
        ttk.Button(buttons, text='Stock alerts', command=self.stock_alerts).pack(side='left', padx=6)
        ttk.Button(buttons, text='Stock valuation', command=self.stock_valuation).pack(side='left', padx=6)
        self.search = tk.StringVar()
        search_frame = ttk.Frame(self.products)
        search_frame.pack(fill='x')
        ttk.Label(search_frame, text='Search:').pack(side='left')
        search_box = ttk.Entry(search_frame, textvariable=self.search, width=35)
        search_box.pack(side='left', padx=8)
        search_box.bind('<KeyRelease>', lambda e: self.refresh_products())
        self.product_tree = self.tree(self.products, ('id','barcode','name','price','cost','stock','unit'), (50,150,270,100,100,90,70))
        self.product_tree.bind('<<TreeviewSelect>>', self.select_product)

    def make_history(self):
        bar = ttk.Frame(self.history)
        bar.pack(fill='x')
        ttk.Button(bar, text='Refresh', command=self.refresh_all_reports).pack(side='left')
        ttk.Button(bar, text='View selected receipt', command=self.view_sale).pack(side='left', padx=6)
        ttk.Button(bar, text='Print selected receipt', command=self.print_selected_sale).pack(side='left', padx=6)
        ttk.Button(bar, text='Export sales CSV', command=self.export_csv).pack(side='left')
        ttk.Button(bar, text='Backup database', command=self.backup_database).pack(side='left', padx=6)
        filters = ttk.Frame(self.history)
        filters.pack(fill='x', pady=7)
        ttk.Label(filters, text='Date (YYYY-MM-DD, blank = all):').pack(side='left')
        self.history_date = tk.StringVar()
        ttk.Entry(filters, textvariable=self.history_date, width=15).pack(side='left', padx=7)
        ttk.Button(filters, text='Apply filter', command=self.refresh_history).pack(side='left')
        ttk.Button(filters, text='Show all', command=self.clear_history_filter).pack(side='left', padx=7)
        self.stats = ttk.Label(self.history, text='', font=('Segoe UI', 12, 'bold'))
        self.stats.pack(anchor='w', pady=10)
        self.sales_tree = self.tree(self.history, ('bill','date','cashier','payment','subtotal','discount','total'), (65,175,125,110,115,110,120))

    def make_dashboard(self):
        top = ttk.Frame(self.dashboard)
        top.pack(fill='x', pady=(0, 10))
        ttk.Label(top, text='Sales & Profit Dashboard', font=('Segoe UI', 18, 'bold')).pack(side='left')
        ttk.Button(top, text='Refresh Dashboard', command=self.refresh_dashboard).pack(side='right')
        summary = ttk.Frame(self.dashboard)
        summary.pack(fill='x', pady=8)
        self.dashboard_labels = {}
        for index, (key, heading) in enumerate((
            ('sales', 'Today Sales'), ('profit', 'Estimated Gross Profit'),
            ('bills', 'Today Bills'), ('low', 'Low Stock Products'))):
            frame = ttk.LabelFrame(summary, text=heading, padding=12)
            frame.grid(row=0, column=index, sticky='nsew', padx=5)
            summary.columnconfigure(index, weight=1)
            value = ttk.Label(frame, text='...', font=('Segoe UI', 15, 'bold'))
            value.pack(anchor='w')
            self.dashboard_labels[key] = value
        ttk.Label(self.dashboard, text='Last 7 days: daily sales (LKR)', font=('Segoe UI', 12, 'bold')).pack(anchor='w', pady=(16, 5))
        self.chart = tk.Canvas(self.dashboard, height=285, background='white', highlightthickness=1, highlightbackground='#dddddd')
        self.chart.pack(fill='both', expand=True, pady=(0, 8))
        self.chart.bind('<Configure>', lambda event: self.draw_chart())
        self.dashboard_days = []
        ttk.Label(self.dashboard, text='Gross profit includes recorded refunds and returned goods cost; shop expenses are shown in Advanced Reports.',
                  foreground='#555').pack(anchor='w')

    def refresh_all_reports(self):
        self.refresh_history()
        self.refresh_dashboard()

    def refresh_dashboard(self):
        from datetime import timedelta
        today = datetime.now().date()
        start = (today - timedelta(days=6)).isoformat()
        with connection() as con:
            sales = con.execute('SELECT COALESCE(SUM(total),0) FROM sales WHERE substr(created,1,10)=?', (today.isoformat(),)).fetchone()[0]
            bills = con.execute('SELECT COUNT(*) FROM sales WHERE substr(created,1,10)=?', (today.isoformat(),)).fetchone()[0]
            gross = con.execute('''SELECT COALESCE(SUM(si.total-si.cost*si.qty),0)
                 FROM sale_items si JOIN sales s ON si.sale_id=s.id
                 WHERE substr(s.created,1,10)=?''', (today.isoformat(),)).fetchone()[0]
            discounts = con.execute('SELECT COALESCE(SUM(discount),0) FROM sales WHERE substr(created,1,10)=?', (today.isoformat(),)).fetchone()[0]
            low = con.execute('SELECT COUNT(*) FROM products WHERE stock<=5').fetchone()[0]
            rows = con.execute('''SELECT substr(created,1,10) AS day, SUM(total) AS total
                 FROM sales WHERE substr(created,1,10)>=? GROUP BY substr(created,1,10)''', (start,)).fetchall()
        self.dashboard_labels['sales'].config(text=rupees(sales))
        with connection() as con:
            refund = con.execute('SELECT COALESCE(SUM(refund),0) FROM returns WHERE substr(created,1,10)=?', (today.isoformat(),)).fetchone()[0]
            return_cost = con.execute('SELECT COALESCE(SUM(cost*qty),0) FROM returns WHERE substr(created,1,10)=?', (today.isoformat(),)).fetchone()[0]
            expenses = con.execute('SELECT COALESCE(SUM(amount),0) FROM expenses WHERE substr(created,1,10)=?', (today.isoformat(),)).fetchone()[0]
        self.dashboard_labels['profit'].config(text=rupees(gross-discounts-refund+return_cost))
        self.dashboard_labels['bills'].config(text=str(bills))
        self.dashboard_labels['low'].config(text=str(low))
        lookup = {r['day']: r['total'] for r in rows}
        self.dashboard_days = [((today-timedelta(days=6-i)).strftime('%a %d'),
                                float(lookup.get((today-timedelta(days=6-i)).isoformat(), 0))) for i in range(7)]
        self.draw_chart()

    def draw_chart(self):
        if not hasattr(self, 'dashboard_days') or not self.dashboard_days:
            return
        canvas = self.chart
        canvas.delete('all')
        width = max(canvas.winfo_width(), 550)
        height = max(canvas.winfo_height(), 250)
        left, right, top, bottom = 75, 20, 25, 55
        plot_w, plot_h = width-left-right, height-top-bottom
        values = [v for _, v in self.dashboard_days]
        max_val = max(max(values), 1)
        for i in range(5):
            y = top + plot_h*i/4
            amount = max_val*(4-i)/4
            canvas.create_line(left, y, width-right, y, fill='#e6e6e6')
            canvas.create_text(left-8, y, text=f'{amount:,.0f}', anchor='e', fill='#666')
        step = plot_w/7
        for i, (label, value) in enumerate(self.dashboard_days):
            x0 = left + i*step + step*.2
            x1 = left + (i+1)*step - step*.2
            y1 = top + plot_h
            y0 = y1 - value/max_val*plot_h
            canvas.create_rectangle(x0, y0, x1, y1, fill='#23876b', outline='')
            canvas.create_text((x0+x1)/2, y1+18, text=label, fill='#333')
            if value:
                canvas.create_text((x0+x1)/2, max(12, y0-10), text=f'{value:,.0f}', font=('Segoe UI', 9))

    def product_data(self):
        barcode = self.pvars['barcode'].get().strip()
        name = self.pvars['name'].get().strip()
        unit = self.pvars['unit'].get().strip().lower()
        if not barcode or not name or unit not in ('pcs','kg'):
            raise ValueError('Enter barcode, name, and unit (pcs or kg).')
        price = float(self.pvars['price'].get())
        cost = float(self.pvars['cost'].get())
        stock = float(self.pvars['stock'].get())
        if not all(math.isfinite(x) for x in (price, cost, stock)) or min(price, cost, stock) < 0:
            raise ValueError('Prices and stock must be non-negative.')
        if unit == 'pcs' and not stock.is_integer():
            raise ValueError('Stock must be a whole number for pcs.')
        return barcode, name, price, cost, stock, unit

    def save_product(self, update=False):
        if self.user['role'] != 'admin':
            return
        if self.user['role'] != 'admin':
            messagebox.showerror('Access denied', 'Only admin can edit products.')
            return
        try:
            values = self.product_data()
            if update:
                selected = self.product_tree.selection()
                if not selected:
                    raise ValueError('Select a product to update.')
                pid = self.product_tree.item(selected[0], 'values')[0]
                with connection() as con:
                    con.execute('UPDATE products SET barcode=?,name=?,price=?,cost=?,stock=?,unit=? WHERE id=?', (*values,pid))
            else:
                with connection() as con:
                    con.execute('INSERT INTO products(barcode,name,price,cost,stock,unit) VALUES (?,?,?,?,?,?)', values)
            self.refresh_products()
            self.clear_form()
            messagebox.showinfo('Saved', 'Product saved successfully.')
        except (ValueError, sqlite3.IntegrityError) as e:
            messagebox.showerror('Product error', str(e))

    def select_product(self, event=None):
        selected = self.product_tree.selection()
        if selected:
            row = self.product_tree.item(selected[0], 'values')
            for key, val in zip(('id','barcode','name','price','cost','stock','unit'), row):
                if key in self.pvars:
                    self.pvars[key].set(str(val))

    def clear_form(self):
        for key, var in self.pvars.items():
            var.set('pcs' if key=='unit' else '0' if key in ('cost','stock') else '')
        for item in self.product_tree.selection():
            self.product_tree.selection_remove(item)

    def delete_product(self):
        if self.user['role'] != 'admin':
            return
        if self.user['role'] != 'admin':
            messagebox.showerror('Access denied', 'Only admin can delete products.')
            return
        selected = self.product_tree.selection()
        if not selected:
            return
        if not messagebox.askyesno('Delete', 'Delete selected product? Previous bills will be kept.'):
            return
        pid = self.product_tree.item(selected[0], 'values')[0]
        with connection() as con:
            con.execute('DELETE FROM products WHERE id=?', (pid,))
        self.refresh_products()
        self.clear_form()

    def refresh_products(self):
        self.product_tree.delete(*self.product_tree.get_children())
        term = '%' + self.search.get().strip() + '%'
        with connection() as con:
            rows = con.execute('SELECT * FROM products WHERE barcode LIKE ? OR name LIKE ? ORDER BY name', (term,term)).fetchall()
        for r in rows:
            self.product_tree.insert('', 'end', values=(r['id'],r['barcode'],r['name'],r['price'],r['cost'],r['stock'],r['unit']))

    def add_to_cart(self):
        query = self.scan_var.get().strip()
        try:
            quantity = float(self.qty.get())
            if not query or not math.isfinite(quantity) or quantity <= 0:
                raise ValueError('Enter a barcode/name and a quantity greater than zero.')
            with connection() as con:
                row = con.execute('SELECT * FROM products WHERE barcode=?', (query,)).fetchone()
                if row is None:
                    matches = con.execute('SELECT * FROM products WHERE name LIKE ? ORDER BY name LIMIT 2', ('%'+query+'%',)).fetchall()
                    if len(matches) != 1:
                        raise ValueError('Product not found or name is ambiguous. Scan the exact barcode.')
                    row = matches[0]
            if row['unit']=='pcs' and not quantity.is_integer():
                raise ValueError('For pcs, quantity must be a whole number.')
            existing = self.cart.get(row['id'])
            current = existing['qty'] if existing else 0
            if current + quantity > row['stock'] + 1e-9:
                raise ValueError(f"Not enough stock. Available: {row['stock']} {row['unit']}")
            if existing:
                existing['qty'] += quantity
            else:
                self.cart[row['id']] = dict(row) | {'qty':quantity}
            self.scan_var.set('')
            self.qty.set('1')
            self.refresh_cart()
            self.scan.focus_set()
        except ValueError as e:
            messagebox.showerror('Cannot add item', str(e))

    def refresh_cart(self):
        self.cart_tree.delete(*self.cart_tree.get_children())
        for pid, item in self.cart.items():
            self.cart_tree.insert('', 'end', iid=str(pid), values=(item['barcode'],item['name'],f"{item['qty']:g}",item['unit'],f"{item['price']:.2f}",f"{item['price']*item['qty']:.2f}"))
        subtotal = sum(x['price']*x['qty'] for x in self.cart.values())
        try:
            discount = float(self.discount.get().strip() or '0')
            if not math.isfinite(discount):
                discount = 0
        except ValueError:
            discount = 0
        self.total_label.config(text='Total: '+rupees(max(0, subtotal-max(0,discount))))
        self.update_balance()

    def update_balance(self):
        if not hasattr(self, 'balance_label'):
            return
        if self.payment_method.get() != 'Cash':
            self.balance_label.config(text='Balance: Not applicable (non-cash)')
            return
        subtotal = sum(item['price'] * item['qty'] for item in self.cart.values())
        try:
            discount = float(self.discount.get().strip() or '0')
            if not math.isfinite(discount) or discount < 0 or discount > subtotal:
                self.balance_label.config(text='Balance: Check discount')
                return
            total = round(subtotal - discount, 2)
            cash_text = self.cash_received.get().strip()
            paid = float(cash_text) if cash_text else total
            if not math.isfinite(paid) or paid < 0:
                raise ValueError('Invalid cash')
            if paid < total:
                self.balance_label.config(text='Cash short: ' + rupees(total - paid))
            else:
                self.balance_label.config(text='Balance: ' + rupees(paid - total))
        except ValueError:
            self.balance_label.config(text='Balance: Enter valid cash amount')

    def remove_item(self):
        for pid in self.cart_tree.selection():
            self.cart.pop(int(pid), None)
        self.refresh_cart()

    def clear_bill(self):
        self.cart.clear()
        self.discount.set('0')
        self.refresh_cart()

    def complete_sale(self):
        if not self.cart:
            messagebox.showwarning('Empty bill', 'Add items first.')
            return
        try:
            discount = float(self.discount.get().strip() or '0')
            if not math.isfinite(discount):
                raise ValueError('Enter a valid discount amount.')
            subtotal = round(sum(x['price']*x['qty'] for x in self.cart.values()),2)
            if not 0 <= discount <= subtotal:
                raise ValueError('Discount must be between 0 and subtotal.')
            discount = round(discount,2)
            total = round(subtotal-discount,2)
            method = self.payment_method.get()
            if method not in ('Cash', 'Card', 'Bank Transfer', 'Credit'):
                raise ValueError('Select a valid payment method.')
            paid = None
            change_due = None
            if method == 'Cash':
                paid = float(self.cash_received.get().strip() or str(total))
                if not math.isfinite(paid) or paid < total:
                    raise ValueError('Cash received must be at least the bill total.')
                paid = round(paid, 2)
                change_due = round(paid - total, 2)
            customer_id = None
            if method == 'Credit':
                customer_id = self.selected_customer_id()
                if customer_id is None:
                    raise ValueError('Select a customer before saving a credit sale.')
                if not messagebox.askyesno('Confirm credit sale', f'Record {rupees(total)} as unpaid credit for this customer?'):
                    return
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with connection() as con:
                con.execute('BEGIN IMMEDIATE')
                for item in self.cart.values():
                    result = con.execute('UPDATE products SET stock=stock-? WHERE id=? AND stock>=?', (item['qty'],item['id'],item['qty']))
                    if result.rowcount != 1:
                        raise ValueError('Stock changed or product deleted: '+item['name'])
                cur = con.execute('INSERT INTO sales(created,subtotal,discount,total,cashier,payment_method,paid,change_due) VALUES (?,?,?,?,?,?,?,?)', (now,subtotal,discount,total,self.user['username'],method,paid,change_due))
                sale_id = cur.lastrowid
                if customer_id is not None:
                    con.execute('UPDATE sales SET customer_id=? WHERE id=?', (customer_id, sale_id))
                for item in self.cart.values():
                    con.execute('INSERT INTO sale_items(sale_id,product_id,barcode,name,qty,price,cost,total) VALUES (?,?,?,?,?,?,?,?)',
                        (sale_id,item['id'],item['barcode'],item['name'],item['qty'],item['price'],item['cost'],round(item['qty']*item['price'],2)))
            receipt = self.receipt_text(sale_id)
            RECEIPTS.mkdir(exist_ok=True)
            path = RECEIPTS / f'receipt_{sale_id}.txt'
            path.write_text(receipt, encoding='utf-8')
            self.last_receipt = receipt
            self.clear_bill()
            self.cash_received.set('')
            self.refresh_products()
            self.refresh_history()
            self.refresh_dashboard()
            self.refresh_advanced()
            self.refresh_credit()
            self.show_receipt(receipt)
        except (ValueError, sqlite3.Error) as e:
            messagebox.showerror('Sale not completed', str(e))

    def receipt_text(self, sale_id):
        with connection() as con:
            sale = con.execute('SELECT * FROM sales WHERE id=?', (sale_id,)).fetchone()
            items = con.execute('SELECT * FROM sale_items WHERE sale_id=?', (sale_id,)).fetchall()
        with connection() as con:
            details = {r['key']: r['value'] for r in con.execute("SELECT key,value FROM settings WHERE key IN ('shop_address','shop_phone')")}
            refunds = con.execute('SELECT COALESCE(SUM(refund),0) FROM returns WHERE sale_id=?', (sale_id,)).fetchone()[0]
        lines = ['='*45, self.shop_name(), details.get('shop_address', ''),
                 'Phone: '+details['shop_phone'] if details.get('shop_phone') else '',
                 'SALES RECEIPT',f"Bill: {sale_id}   Date: {sale['created']}",'-'*45]
        lines = [line for line in lines if line]
        for x in items:
            lines.append(f"{x['name']} ({x['qty']:g}) @ {rupees(x['price'])}")
            lines.append(f"  Line total: {rupees(x['total'])}")
        lines += ['-'*45, 'Subtotal: '+rupees(sale['subtotal']), 'Discount: '+rupees(sale['discount']), 'TOTAL: '+rupees(sale['total'])]
        if refunds:
            lines.append('Refunds issued: '+rupees(refunds))
            lines.append('Net after refunds: '+rupees(sale['total']-refunds))
        lines.append('Cashier: ' + (sale['cashier'] or 'Unknown (older sale)'))
        lines.append('Payment: ' + sale['payment_method'])
        if sale['payment_method'] == 'Credit':
            with connection() as con:
                cust = con.execute('SELECT name FROM customers WHERE id=?', (sale['customer_id'],)).fetchone()
                paid_credit = con.execute('SELECT COALESCE(SUM(amount),0) FROM credit_payments WHERE sale_id=?', (sale_id,)).fetchone()[0]
            lines.append('Credit customer: ' + (cust['name'] if cust else 'Unknown'))
            lines.append('Credit balance: ' + rupees(max(0, sale['total']-paid_credit)))
        if sale['paid'] is not None:
            lines += ['Received: '+rupees(sale['paid']), 'Change: '+rupees(sale['change_due'])]
        lines += ['='*45, 'Thank you!']
        return '\n'.join(lines)

    def show_receipt(self, content):
        window = tk.Toplevel(self.root)
        window.title('Receipt')
        window.geometry('550x540')
        box = tk.Text(window, font=('Consolas',11))
        box.pack(fill='both', expand=True, padx=10, pady=10)
        box.insert('1.0',content)
        box.config(state='disabled')

    def shop_name(self):
        with connection() as con:
            row = con.execute("SELECT value FROM settings WHERE key='shop_name'").fetchone()
        return row['value'] if row else 'GROCERY SHOP'

    def make_settings(self):
        panel = ttk.LabelFrame(self.settings_tab, text='Shop details', padding=12)
        panel.pack(fill='x')
        ttk.Label(panel, text='Shop name (shown on receipts):').pack(anchor='w')
        self.shop_name_var = tk.StringVar(value=self.shop_name())
        ttk.Entry(panel, textvariable=self.shop_name_var, width=45).pack(anchor='w', pady=5)
        save = ttk.Button(panel, text='Save Shop Name', command=self.save_shop_name)
        save.pack(anchor='w', pady=5)
        with connection() as con:
            stored = {r['key']:r['value'] for r in con.execute("SELECT key,value FROM settings WHERE key IN ('shop_address','shop_phone')")}
        self.address_var = tk.StringVar(value=stored.get('shop_address',''))
        self.phone_var = tk.StringVar(value=stored.get('shop_phone',''))
        ttk.Label(panel, text='Address / Phone for receipts:').pack(anchor='w')
        contact = ttk.Frame(panel)
        contact.pack(anchor='w')
        ttk.Entry(contact, textvariable=self.address_var, width=52).pack(side='left', padx=(0,8))
        ttk.Entry(contact, textvariable=self.phone_var, width=22).pack(side='left', padx=(0,8))
        contact_save = ttk.Button(contact, text='Save Contact', command=self.save_contact)
        contact_save.pack(side='left')
        if self.user['role'] != 'admin':
            contact_save.state(['disabled'])
        if self.user['role'] != 'admin':
            save.state(['disabled'])
        printer_panel = ttk.LabelFrame(self.settings_tab, text='Receipt printer settings', padding=12)
        printer_panel.pack(fill='x', pady=10)
        ttk.Label(printer_panel, text='Printing mode:').pack(anchor='w')
        with connection() as con:
            row = con.execute("SELECT value FROM settings WHERE key='printer_mode'").fetchone()
        self.printer_mode = tk.StringVar(value=row['value'] if row else 'save_only')
        ttk.Radiobutton(printer_panel, text='Save receipts only (no printer)', variable=self.printer_mode,
                        value='save_only').pack(anchor='w')
        ttk.Radiobutton(printer_panel, text='Windows default printer (when installed)', variable=self.printer_mode,
                        value='windows_default').pack(anchor='w')
        btn = ttk.Button(printer_panel, text='Save Printer Settings', command=self.save_printer_settings)
        btn.pack(anchor='w', pady=6)
        if self.user['role'] != 'admin':
            btn.state(['disabled'])
        ttk.Label(printer_panel, text='For thermal printers, install the correct Windows driver and set paper size to 80mm in printer preferences.',
                  foreground='#555', wraplength=850).pack(anchor='w')

        if self.user['role'] == 'admin':
            staff = ttk.LabelFrame(self.settings_tab, text='Create staff account', padding=12)
            staff.pack(fill='x')
            self.staff_name = tk.StringVar()
            self.staff_pass = tk.StringVar()
            ttk.Label(staff, text='Username').grid(row=0, column=0, sticky='w', padx=5)
            ttk.Entry(staff, textvariable=self.staff_name).grid(row=1, column=0, padx=5)
            ttk.Label(staff, text='Password (min 8 characters)').grid(row=0, column=1, sticky='w', padx=5)
            ttk.Entry(staff, textvariable=self.staff_pass, show='*').grid(row=1, column=1, padx=5)
            ttk.Button(staff, text='Add Cashier', command=self.add_cashier).grid(row=1, column=2, padx=12)
            ttk.Label(staff, text='Cashiers can create bills and view sales; product editing is restricted to admin.',
                      foreground='#555').grid(row=2, column=0, columnspan=3, sticky='w', pady=8)
            password_box = ttk.LabelFrame(self.settings_tab, text='Change my password', padding=12)
            password_box.pack(fill='x', pady=12)
            self.old_password = tk.StringVar()
            self.new_password = tk.StringVar()
            ttk.Label(password_box, text='Current password').grid(row=0, column=0, sticky='w')
            ttk.Entry(password_box, textvariable=self.old_password, show='*').grid(row=1, column=0, padx=(0, 10))
            ttk.Label(password_box, text='New password (min 8 characters)').grid(row=0, column=1, sticky='w')
            ttk.Entry(password_box, textvariable=self.new_password, show='*').grid(row=1, column=1, padx=(0, 10))
            ttk.Button(password_box, text='Change Password', command=self.change_password).grid(row=1, column=2)

    def save_contact(self):
        if self.user['role'] != 'admin':
            return
        address, phone = self.address_var.get().strip(), self.phone_var.get().strip()
        if len(address)>120 or len(phone)>35:
            messagebox.showerror('Contact', 'Address or phone is too long.')
            return
        with connection() as con:
            con.execute("INSERT OR REPLACE INTO settings VALUES ('shop_address',?)", (address,))
            con.execute("INSERT OR REPLACE INTO settings VALUES ('shop_phone',?)", (phone,))
        messagebox.showinfo('Saved', 'Receipt contact details saved.')

    def save_printer_settings(self):
        if self.user['role'] != 'admin':
            return
        with connection() as con:
            con.execute("INSERT OR REPLACE INTO settings(key,value) VALUES ('printer_mode',?)", (self.printer_mode.get(),))
        messagebox.showinfo('Printer', 'Printer settings saved.')

    def save_shop_name(self):
        if self.user['role'] != 'admin':
            return
        name = self.shop_name_var.get().strip()
        if not name or len(name) > 60:
            messagebox.showerror('Shop name', 'Enter a shop name (1-60 characters).')
            return
        with connection() as con:
            con.execute("INSERT OR REPLACE INTO settings(key,value) VALUES ('shop_name',?)", (name,))
        messagebox.showinfo('Saved', 'Shop name saved. New receipt previews will use it.')

    def add_cashier(self):
        if self.user['role'] != 'admin':
            return
        username, password = self.staff_name.get().strip(), self.staff_pass.get()
        if not username or len(password) < 8:
            messagebox.showerror('Staff', 'Enter a username and password of at least 8 characters.')
            return
        try:
            with connection() as con:
                con.execute('INSERT INTO users(username,password_hash,role) VALUES (?,?,?)',
                            (username, hash_password(password), 'cashier'))
        except sqlite3.IntegrityError:
            messagebox.showerror('Staff', 'That username already exists.')
            return
        self.staff_name.set('')
        self.staff_pass.set('')
        messagebox.showinfo('Staff', 'Cashier account created.')

    def change_password(self):
        with connection() as con:
            row = con.execute('SELECT password_hash FROM users WHERE username=?', (self.user['username'],)).fetchone()
            if not row or not verify_password(self.old_password.get(), row['password_hash']):
                messagebox.showerror('Password', 'Current password is incorrect.')
                return
            if len(self.new_password.get()) < 8:
                messagebox.showerror('Password', 'New password must have at least 8 characters.')
                return
            con.execute('UPDATE users SET password_hash=? WHERE username=?',
                        (hash_password(self.new_password.get()), self.user['username']))
        self.old_password.set('')
        self.new_password.set('')
        messagebox.showinfo('Password', 'Password updated.')

    def print_receipt(self, content):
        with connection() as con:
            row = con.execute("SELECT value FROM settings WHERE key='printer_mode'").fetchone()
        if not row or row['value'] == 'save_only':
            messagebox.showinfo('Printer', 'Printer is set to Save Only. Receipts are saved in the receipts folder.\nChange the printer mode in Settings / Staff when you install a printer.')
            return
        if os.name != 'nt':
            messagebox.showerror('Printer', 'Windows printing is supported on Windows only.')
            return
        if not messagebox.askyesno('Print receipt', 'Send this receipt to the Windows DEFAULT printer?\n\nConfigure the printer in Windows Settings first.'):
            return
        PRINT_DIR.mkdir(exist_ok=True)
        path = PRINT_DIR / ('print_' + datetime.now().strftime('%Y%m%d_%H%M%S_%f') + '.txt')
        try:
            path.write_text(content, encoding='utf-8')
            os.startfile(str(path), 'print')
            messagebox.showinfo('Print request', 'Print request sent to Windows. Check the printer queue.\n\nFor thermal printers, install the driver and set it as default.')
        except (OSError, ValueError) as exc:
            messagebox.showerror('Printer', 'Could not send print job: ' + str(exc))

    def print_last(self):
        if not self.last_receipt:
            messagebox.showinfo('Receipt', 'Complete a sale first, or print a selected receipt in Sales / Reports.')
            return
        self.print_receipt(self.last_receipt)

    def print_selected_sale(self):
        selected = self.sales_tree.selection()
        if not selected:
            messagebox.showinfo('Receipt', 'Select a sale first.')
            return
        sale_id = self.sales_tree.item(selected[0], 'values')[0]
        self.print_receipt(self.receipt_text(sale_id))

    def logout(self):
        if self.cart and not messagebox.askyesno('Logout', 'The current unsaved bill will be cleared. Log out?'):
            return
        self.root.destroy()

    def view_last(self):
        if self.last_receipt:
            self.show_receipt(self.last_receipt)
        else:
            messagebox.showinfo('Receipt', 'Complete a sale first or select one from Sales / Reports.')

    def clear_history_filter(self):
        self.history_date.set('')
        self.refresh_history()

    def refresh_history(self):
        date = self.history_date.get().strip()
        if date:
            try:
                datetime.strptime(date, '%Y-%m-%d')
            except ValueError:
                messagebox.showerror('Date filter', 'Use YYYY-MM-DD, e.g. 2026-10-13.')
                return
        self.sales_tree.delete(*self.sales_tree.get_children())
        with connection() as con:
            if date:
                rows = con.execute('SELECT * FROM sales WHERE created LIKE ? ORDER BY id DESC', (date+'%',)).fetchall()
            else:
                rows = con.execute('SELECT * FROM sales ORDER BY id DESC').fetchall()
            today = datetime.now().strftime('%Y-%m-%d')
            daily = con.execute('SELECT COALESCE(SUM(total),0) AS amount FROM sales WHERE created LIKE ?', (today+'%',)).fetchone()['amount']
            profit = con.execute('''SELECT COALESCE(SUM(si.total-si.cost*si.qty),0) AS amount
               FROM sale_items si JOIN sales s ON s.id=si.sale_id WHERE s.created LIKE ?''', (today+'%',)).fetchone()['amount']
            discounts = con.execute('SELECT COALESCE(SUM(discount),0) AS amount FROM sales WHERE created LIKE ?', (today+'%',)).fetchone()['amount']
        self.stats.config(text=f'Today sales: {rupees(daily)}    Estimated gross profit: {rupees(profit-discounts)}')
        for r in rows:
            self.sales_tree.insert('', 'end', values=(r['id'],r['created'],r['cashier'] or '-',r['payment_method'],f"{r['subtotal']:.2f}",f"{r['discount']:.2f}",f"{r['total']:.2f}"))

    def view_sale(self):
        selected = self.sales_tree.selection()
        if selected:
            sale_id = self.sales_tree.item(selected[0],'values')[0]
            self.show_receipt(self.receipt_text(sale_id))

    def low_stock_report(self):
        with connection() as con:
            rows = con.execute('SELECT name,barcode,stock,unit FROM products WHERE stock <= 5 ORDER BY stock,name').fetchall()
        if not rows:
            messagebox.showinfo('Low stock report', 'No products with 5 or fewer units remaining.')
            return
        content = 'LOW STOCK REPORT (5 or fewer units)\n' + '-'*45 + '\n'
        content += '\n'.join(f"{r['name']} | {r['barcode']} | {r['stock']:g} {r['unit']}" for r in rows)
        self.show_receipt(content)

    def backup_database(self):
        destination = filedialog.asksaveasfilename(
            title='Save database backup', defaultextension='.db',
            initialfile='grocery_backup_' + datetime.now().strftime('%Y%m%d_%H%M%S') + '.db',
            filetypes=[('SQLite database','*.db')])
        if not destination:
            return
        try:
            with connection() as source, sqlite3.connect(destination) as target:
                source.backup(target)
            messagebox.showinfo('Backup complete', 'Database backup saved successfully.')
        except (OSError, sqlite3.Error) as exc:
            messagebox.showerror('Backup failed', str(exc))

    def stock_valuation(self):
        with connection() as con:
            row = con.execute('SELECT COUNT(*) AS n, COALESCE(SUM(stock*cost),0) AS cost, COALESCE(SUM(stock*price),0) AS retail FROM products').fetchone()
        messagebox.showinfo('Stock valuation', f"Products: {row['n']}\nStock at buying cost: {rupees(row['cost'])}\nStock at selling price: {rupees(row['retail'])}\n\nCost valuation depends on accurate cost prices.")

    def export_stock_csv(self):
        path = filedialog.asksaveasfilename(title='Export stock', defaultextension='.csv', filetypes=[('CSV','*.csv')])
        if not path:
            return
        try:
            with connection() as con:
                rows = con.execute('SELECT barcode,name,price,cost,stock,unit FROM products ORDER BY name').fetchall()
            with open(path, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                writer.writerow(['Barcode','Product','Selling price LKR','Buying cost LKR','Stock','Unit','Stock cost value LKR'])
                for r in rows:
                    writer.writerow([r['barcode'],r['name'],r['price'],r['cost'],r['stock'],r['unit'],round(r['stock']*r['cost'],2)])
            messagebox.showinfo('Exported', 'Stock CSV saved.')
        except OSError as exc:
            messagebox.showerror('Export failed', str(exc))

    def export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension='.csv',filetypes=[('CSV','*.csv')])
        if not path:
            return
        with connection() as con:
            rows = con.execute('SELECT * FROM sales ORDER BY id').fetchall()
        with open(path,'w',newline='',encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            writer.writerow(['Bill','Date','Cashier','Payment method','Subtotal LKR','Discount LKR','Total LKR','Received LKR','Change LKR'])
            for r in rows:
                writer.writerow([r['id'],r['created'],r['cashier'],r['payment_method'],r['subtotal'],r['discount'],r['total'],r['paid'],r['change_due']])
        messagebox.showinfo('Exported', 'Sales CSV saved.')

    def make_returns(self):
        ttk.Label(self.returns_tab, text='Sales Returns / Refunds', font=('Segoe UI',16,'bold')).pack(anchor='w')
        ttk.Label(self.returns_tab, text='Refund is proportional to the original bill discount. Full/partial item returns; stock restored.').pack(anchor='w', pady=6)
        bar = ttk.Frame(self.returns_tab); bar.pack(fill='x', pady=8)
        self.return_bill = tk.StringVar(); self.return_qty = tk.StringVar(value='1'); self.return_reason = tk.StringVar(value='Customer return')
        for label,var,width in [('Bill ID',self.return_bill,10),('Return quantity',self.return_qty,12),('Reason',self.return_reason,30)]:
            ttk.Label(bar,text=label).pack(side='left',padx=3)
            ttk.Entry(bar,textvariable=var,width=width).pack(side='left',padx=4)
        ttk.Button(bar,text='Load bill items',command=self.load_return_items).pack(side='left',padx=8)
        self.return_tree = self.tree(self.returns_tab, ('item_id','product','sold','returned','remaining','unit','refund_per_unit'), (75,270,90,95,100,65,140))
        ttk.Button(self.returns_tab,text='REFUND SELECTED ITEM (RESTORE STOCK)',command=self.process_return).pack(fill='x',pady=8)

    def load_return_items(self):
        try:
            bill = int(self.return_bill.get())
            if bill<=0: raise ValueError()
        except ValueError:
            messagebox.showerror('Returns','Enter a valid Bill ID.'); return
        self.return_tree.delete(*self.return_tree.get_children())
        with connection() as con:
            sale=con.execute('SELECT subtotal,discount FROM sales WHERE id=?',(bill,)).fetchone()
            if sale is None:
                messagebox.showerror('Returns','Bill not found.'); return
            rows=con.execute('''SELECT si.*, COALESCE(SUM(r.qty),0) AS returned
                FROM sale_items si LEFT JOIN returns r ON r.sale_item_id=si.id
                WHERE si.sale_id=? GROUP BY si.id''',(bill,)).fetchall()
            for r in rows:
                unit=con.execute('SELECT unit FROM products WHERE id=?',(r['product_id'],)).fetchone()
                unit=unit['unit'] if unit else 'pcs'
                rate=1-sale['discount']/sale['subtotal'] if sale['subtotal']>0 else 1
                remaining=max(0,r['qty']-r['returned'])
                self.return_tree.insert('','end',values=(r['id'],r['name'],f"{r['qty']:g}",f"{r['returned']:g}",f'{remaining:g}',unit,f"{r['price']*rate:.2f}"))

    def process_return(self):
        chosen=self.return_tree.selection()
        if not chosen:
            messagebox.showwarning('Returns','Select a bill item.'); return
        try:
            qty=finite_number(self.return_qty.get(),'Return quantity',positive=True)
            item_id=int(self.return_tree.item(chosen[0],'values')[0])
            reason=self.return_reason.get().strip()
            if not reason: raise ValueError('Enter a return reason.')
            with connection() as con:
                con.execute('BEGIN IMMEDIATE')
                item=con.execute('SELECT * FROM sale_items WHERE id=?',(item_id,)).fetchone()
                sale=con.execute('SELECT * FROM sales WHERE id=?',(item['sale_id'],)).fetchone()
                already=con.execute('SELECT COALESCE(SUM(qty),0) FROM returns WHERE sale_item_id=?',(item_id,)).fetchone()[0]
                remaining=item['qty']-already
                if qty>remaining+1e-8: raise ValueError(f'Only {remaining:g} remaining to return.')
                product=con.execute('SELECT unit FROM products WHERE id=?',(item['product_id'],)).fetchone()
                if not product: raise ValueError('Original product no longer exists; manual refund required. No changes made.')
                if product['unit']=='pcs' and not qty.is_integer(): raise ValueError('Pieces require whole quantity.')
                rate=1-sale['discount']/sale['subtotal'] if sale['subtotal'] else 1
                # Cumulative rounding prevents partial-return rounding drift.
                previous_refund=con.execute('SELECT COALESCE(SUM(refund),0) FROM returns WHERE sale_item_id=?',(item_id,)).fetchone()[0]
                target=round(item['total']*rate*(already+qty)/item['qty'],2)
                refund=round(target-previous_refund,2)
                if refund<0: raise ValueError('Refund amount is invalid.')
                if not messagebox.askyesno('Confirm refund',f'Refund {rupees(refund)} for {qty:g} units?\nStock will be restored.'):
                    raise InterruptedError()
                con.execute('UPDATE products SET stock=stock+? WHERE id=?',(qty,item['product_id']))
                con.execute('INSERT INTO returns(sale_item_id,sale_id,created,qty,refund,cost,cashier,reason) VALUES (?,?,?,?,?,?,?,?)',
                    (item_id,item['sale_id'],datetime.now().strftime('%Y-%m-%d %H:%M:%S'),qty,refund,item['cost'],self.user['username'],reason))
            self.load_return_items(); self.refresh_products(); self.refresh_dashboard(); self.refresh_advanced()
            messagebox.showinfo('Refund recorded',f'Refund: {rupees(refund)}\nStock restored. Return recorded in database.\nPay customer separately; no bank/card refund is processed.')
        except InterruptedError:
            pass
        except (ValueError,sqlite3.Error) as e:
            messagebox.showerror('Return error',str(e))

    def make_expenses(self):
        ttk.Label(self.expenses_tab,text='Shop Expenses',font=('Segoe UI',16,'bold')).pack(anchor='w')
        form=ttk.Frame(self.expenses_tab); form.pack(fill='x',pady=12)
        self.exp_cat=tk.StringVar(value='Utilities'); self.exp_desc=tk.StringVar(); self.exp_amount=tk.StringVar()
        for label,var,width in [('Category',self.exp_cat,18),('Description',self.exp_desc,40),('Amount Rs.',self.exp_amount,14)]:
            ttk.Label(form,text=label).pack(side='left',padx=4)
            ttk.Entry(form,textvariable=var,width=width).pack(side='left',padx=4)
        ttk.Button(form,text='Save expense',command=self.add_expense).pack(side='left',padx=8)
        self.exp_tree=self.tree(self.expenses_tab,('id','date','category','description','amount','cashier'),(55,170,145,330,115,110))
        ttk.Button(self.expenses_tab,text='Refresh expenses',command=self.refresh_expenses).pack(anchor='w')
        self.refresh_expenses()

    def add_expense(self):
        try:
            amount=round(finite_number(self.exp_amount.get(),'Amount',positive=True),2)
            if amount<=0: raise ValueError('Amount must be at least Rs. 0.01.')
            category=self.exp_cat.get().strip(); desc=self.exp_desc.get().strip()
            if not category or not desc: raise ValueError('Enter category and description.')
            with connection() as con:
                con.execute('INSERT INTO expenses(created,category,description,amount,cashier) VALUES (?,?,?,?,?)',
                    (datetime.now().strftime('%Y-%m-%d %H:%M:%S'),category,desc,amount,self.user['username']))
            self.exp_desc.set(''); self.exp_amount.set(''); self.refresh_expenses(); self.refresh_advanced()
            messagebox.showinfo('Saved','Expense recorded.')
        except (ValueError,sqlite3.Error) as e: messagebox.showerror('Expense error',str(e))

    def refresh_expenses(self):
        self.exp_tree.delete(*self.exp_tree.get_children())
        with connection() as con:
            for r in con.execute('SELECT * FROM expenses ORDER BY id DESC LIMIT 500'):
                self.exp_tree.insert('','end',values=(r['id'],r['created'],r['category'],r['description'],f"{r['amount']:.2f}",r['cashier']))

    def make_purchases(self):
        ttk.Label(self.purchases_tab,text='Stock Purchases (Admin)',font=('Segoe UI',16,'bold')).pack(anchor='w')
        ttk.Label(self.purchases_tab,text='Select a product in Products / Stock first; enter new stock quantity and buying cost here.').pack(anchor='w',pady=6)
        form=ttk.Frame(self.purchases_tab); form.pack(fill='x',pady=12)
        self.buy_barcode=tk.StringVar(); self.buy_qty=tk.StringVar(); self.buy_cost=tk.StringVar(); self.buy_supplier=tk.StringVar()
        for label,var,width in [('Barcode',self.buy_barcode,18),('Quantity',self.buy_qty,12),('Cost per unit',self.buy_cost,14),('Supplier',self.buy_supplier,26)]:
            ttk.Label(form,text=label).pack(side='left',padx=3)
            ttk.Entry(form,textvariable=var,width=width).pack(side='left',padx=3)
        btn=ttk.Button(form,text='Receive Stock',command=self.receive_stock); btn.pack(side='left',padx=8)
        if self.user['role']!='admin': btn.state(['disabled'])
        self.purchase_tree=self.tree(self.purchases_tab,('id','date','barcode','product','qty','unit_cost','supplier'),(55,170,120,220,85,100,170))
        ttk.Button(self.purchases_tab,text='Refresh purchases',command=self.refresh_purchases).pack(anchor='w')
        self.refresh_purchases()

    def receive_stock(self):
        if self.user['role']!='admin': return
        try:
            barcode=self.buy_barcode.get().strip(); supplier=self.buy_supplier.get().strip()
            qty=finite_number(self.buy_qty.get(),'Quantity',positive=True)
            cost=round(finite_number(self.buy_cost.get(),'Unit cost'),2)
            if not barcode or not supplier: raise ValueError('Enter barcode and supplier.')
            with connection() as con:
                con.execute('BEGIN IMMEDIATE')
                product=con.execute('SELECT * FROM products WHERE barcode=?',(barcode,)).fetchone()
                if product is None: raise ValueError('Product not found.')
                if product['unit']=='pcs' and not qty.is_integer(): raise ValueError('Pieces must be whole numbers.')
                if not messagebox.askyesno('Receive stock',f"Add {qty:g} {product['unit']} to {product['name']} at {rupees(cost)} each?"):
                    raise InterruptedError()
                con.execute('UPDATE products SET stock=stock+?,cost=? WHERE id=?',(qty,cost,product['id']))
                sup=con.execute('SELECT id FROM suppliers_v9 WHERE name=?',(supplier,)).fetchone()
                con.execute('INSERT INTO purchases(created,product_id,qty,unit_cost,supplier,cashier,supplier_id_v9) VALUES (?,?,?,?,?,?,?)',
                    (datetime.now().strftime('%Y-%m-%d %H:%M:%S'),product['id'],qty,cost,supplier,self.user['username'],sup['id'] if sup else None))
            self.buy_qty.set(''); self.refresh_purchases(); self.refresh_products(); self.refresh_dashboard(); self.refresh_advanced()
            messagebox.showinfo('Stock received','Purchase saved and stock updated. Cost is updated to latest buying cost (not weighted average).')
        except InterruptedError: pass
        except (ValueError,sqlite3.Error) as e: messagebox.showerror('Purchase error',str(e))

    def refresh_purchases(self):
        self.purchase_tree.delete(*self.purchase_tree.get_children())
        with connection() as con:
            for r in con.execute('''SELECT p.*,x.barcode,x.name FROM purchases p JOIN products x ON x.id=p.product_id ORDER BY p.id DESC LIMIT 500'''):
                self.purchase_tree.insert('','end',values=(r['id'],r['created'],r['barcode'],r['name'],f"{r['qty']:g}",f"{r['unit_cost']:.2f}",r['supplier']))

    def make_advanced(self):
        ttk.Label(self.advanced_tab,text='Advanced Financial Reports',font=('Segoe UI',16,'bold')).pack(anchor='w')
        controls=ttk.Frame(self.advanced_tab); controls.pack(fill='x',pady=12)
        self.report_start=tk.StringVar(value=datetime.now().strftime('%Y-%m-01'))
        self.report_end=tk.StringVar(value=datetime.now().strftime('%Y-%m-%d'))
        for label,var in [('From YYYY-MM-DD',self.report_start),('To YYYY-MM-DD',self.report_end)]:
            ttk.Label(controls,text=label).pack(side='left',padx=5)
            ttk.Entry(controls,textvariable=var,width=13).pack(side='left',padx=5)
        ttk.Button(controls,text='Generate',command=self.refresh_advanced).pack(side='left',padx=8)
        ttk.Button(controls,text='Export CSV',command=self.export_advanced).pack(side='left')
        self.advanced_text=tk.Text(self.advanced_tab,font=('Consolas',12),height=22,wrap='none')
        self.advanced_text.pack(fill='both',expand=True,pady=10)
        self.advanced_text.config(state='disabled')

    def report_data(self):
        start,end=self.report_start.get().strip(),self.report_end.get().strip()
        try:
            for d in (start,end):
                if datetime.strptime(d,'%Y-%m-%d').strftime('%Y-%m-%d')!=d: raise ValueError()
        except ValueError: raise ValueError('Dates must use YYYY-MM-DD.')
        if start>end: raise ValueError('Start date must not be after end date.')
        with connection() as con:
            rows=con.execute('''SELECT substr(created,1,10) AS day,COUNT(*) AS bills,SUM(total) AS sales,SUM(discount) AS discounts
                FROM sales WHERE substr(created,1,10) BETWEEN ? AND ? GROUP BY substr(created,1,10) ORDER BY day''',(start,end)).fetchall()
            sales=sum(r['sales'] for r in rows); bills=sum(r['bills'] for r in rows)
            gross=con.execute('''SELECT COALESCE(SUM(si.total-si.cost*si.qty),0) FROM sale_items si
                JOIN sales s ON s.id=si.sale_id WHERE substr(s.created,1,10) BETWEEN ? AND ?''',(start,end)).fetchone()[0]
            discounts=sum(r['discounts'] for r in rows)
            refunds=con.execute('SELECT COALESCE(SUM(refund),0) FROM returns WHERE substr(created,1,10) BETWEEN ? AND ?',(start,end)).fetchone()[0]
            returned_cost=con.execute('SELECT COALESCE(SUM(cost*qty),0) FROM returns WHERE substr(created,1,10) BETWEEN ? AND ?',(start,end)).fetchone()[0]
            expenses=con.execute('SELECT COALESCE(SUM(amount),0) FROM expenses WHERE substr(created,1,10) BETWEEN ? AND ?',(start,end)).fetchone()[0]
            purchases=con.execute('SELECT COALESCE(SUM(qty*unit_cost),0) FROM purchases WHERE substr(created,1,10) BETWEEN ? AND ?',(start,end)).fetchone()[0]
        return {'start':start,'end':end,'rows':rows,'sales':sales,'bills':bills,'discounts':discounts,'refunds':refunds,'returned_cost':returned_cost,'expenses':expenses,'purchases':purchases,'gross_profit':gross-discounts-refunds+returned_cost,'net_estimate':gross-discounts-refunds+returned_cost-expenses}

    def refresh_advanced(self):
        try: data=self.report_data()
        except (ValueError,sqlite3.Error) as e:
            messagebox.showerror('Reports',str(e)); return
        lines=[f"MALKANTHI STORES - {self.shop_name()}",f"PERIOD: {data['start']} to {data['end']}",'='*65,
            f"Bills:                    {data['bills']}",f"Gross sales:              {rupees(data['sales'])}",
            f"Refunds:                  {rupees(data['refunds'])}",f"Net sales after refunds:  {rupees(data['sales']-data['refunds'])}",
            f"Estimated gross profit:   {rupees(data['gross_profit'])}",f"Shop expenses:            {rupees(data['expenses'])}",
            f"Estimated profit after expenses: {rupees(data['net_estimate'])}",
            f"Stock purchased (cost):   {rupees(data['purchases'])}",'',
            'Daily sales (before refunds):','-'*65]
        for r in data['rows']: lines.append(f"{r['day']}  Bills {r['bills']:>4}  Sales {rupees(r['sales'])}")
        lines+=['','Notes: Estimates depend on accurate item cost prices.','Refunds and expenses are dated when recorded; purchases are inventory, not a direct expense.','No taxes, depreciation, or unpaid supplier balances included.']
        self.advanced_text.config(state='normal'); self.advanced_text.delete('1.0','end')
        self.advanced_text.insert('1.0','\n'.join(lines)); self.advanced_text.config(state='disabled')

    def export_advanced(self):
        try: data=self.report_data()
        except ValueError as e: messagebox.showerror('Reports',str(e)); return
        path=filedialog.asksaveasfilename(defaultextension='.csv',filetypes=[('CSV','*.csv')])
        if not path: return
        try:
            with open(path,'w',newline='',encoding='utf-8-sig') as f:
                w=csv.writer(f); w.writerow(['Start',data['start'],'End',data['end']]);
                for key in ('sales','bills','discounts','refunds','returned_cost','expenses','purchases','gross_profit','net_estimate'):
                    w.writerow([key,data[key]])
                w.writerow([]);w.writerow(['Date','Bills','Sales LKR','Discount LKR'])
                for r in data['rows']: w.writerow([r['day'],r['bills'],r['sales'],r['discounts']])
            messagebox.showinfo('Export','Advanced report CSV saved.')
        except OSError as e: messagebox.showerror('Export',str(e))

    # ---------------- Version 8: inventory alerts ----------------
    def set_min_stock(self):
        if self.user['role'] != 'admin':
            messagebox.showerror('Access denied', 'Admin only.'); return
        selected = self.product_tree.selection()
        if not selected:
            messagebox.showinfo('Stock alerts', 'Select a product first.'); return
        pid = int(self.product_tree.item(selected[0], 'values')[0])
        with connection() as con:
            row = con.execute('SELECT name, min_stock FROM products WHERE id=?', (pid,)).fetchone()
        dialog = tk.Toplevel(self.root); dialog.title('Minimum stock level'); dialog.geometry('360x155'); dialog.transient(self.root); dialog.grab_set()
        ttk.Label(dialog, text=row['name'] + ' - minimum stock').pack(pady=9)
        value = tk.StringVar(value=str(row['min_stock']))
        ttk.Entry(dialog, textvariable=value).pack()
        def save():
            try:
                amount = finite_number(value.get(), 'Minimum stock')
                with connection() as con:
                    con.execute('UPDATE products SET min_stock=? WHERE id=?', (amount, pid))
                dialog.destroy(); self.stock_alerts()
            except ValueError as exc: messagebox.showerror('Minimum stock', str(exc), parent=dialog)
        ttk.Button(dialog, text='Save', command=save).pack(pady=12)

    def stock_alerts(self):
        with connection() as con:
            rows = con.execute('SELECT barcode,name,stock,min_stock,unit FROM products WHERE stock<=min_stock ORDER BY stock,name').fetchall()
        if not rows:
            messagebox.showinfo('Inventory alerts', 'All products are above their minimum stock levels.'); return
        lines = ['LOW STOCK ALERTS', '-'*50]
        for r in rows:
            lines.append(f"{r['name']} [{r['barcode']}] - {r['stock']:g} {r['unit']} (minimum {r['min_stock']:g})")
        self.show_receipt('\n'.join(lines))

    # ---------------- Version 8: customer records ----------------
    def make_customers(self):
        box = ttk.LabelFrame(self.customers_tab, text='Add customer', padding=10); box.pack(fill='x')
        self.c_name=tk.StringVar(); self.c_phone=tk.StringVar(); self.c_address=tk.StringVar()
        for i,(label,var) in enumerate([('Customer name',self.c_name),('Phone',self.c_phone),('Address',self.c_address)]):
            ttk.Label(box,text=label).grid(row=0,column=i,padx=6,sticky='w')
            ttk.Entry(box,textvariable=var,width=32).grid(row=1,column=i,padx=6,pady=5)
        ttk.Button(box,text='Add Customer',command=self.add_customer).grid(row=1,column=3,padx=10)
        ttk.Button(self.customers_tab,text='Refresh',command=self.refresh_customers).pack(anchor='w',pady=6)
        self.customer_tree=self.tree(self.customers_tab,('id','name','phone','address'),(65,230,180,300))
        self.refresh_customers()

    def add_customer(self):
        name=self.c_name.get().strip(); phone=self.c_phone.get().strip(); address=self.c_address.get().strip()
        if not name:
            messagebox.showerror('Customer','Enter customer name.'); return
        with connection() as con:
            con.execute('INSERT INTO customers(name,phone,address,created) VALUES (?,?,?,?)',(name,phone,address,datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        self.c_name.set(''); self.c_phone.set(''); self.c_address.set('')
        self.refresh_customers(); self.refresh_customer_combo()
        messagebox.showinfo('Customer','Customer saved.')

    def refresh_customers(self):
        if not hasattr(self,'customer_tree'): return
        self.customer_tree.delete(*self.customer_tree.get_children())
        with connection() as con:
            rows=con.execute('SELECT id,name,phone,address FROM customers ORDER BY name,id').fetchall()
        for r in rows: self.customer_tree.insert('','end',values=tuple(r))

    def refresh_customer_combo(self):
        with connection() as con:
            rows=con.execute('SELECT id,name,phone FROM customers ORDER BY name,id').fetchall()
        self.customer_lookup={f"{r['id']} - {r['name']} ({r['phone']})":r['id'] for r in rows}
        self.customer_combo['values']=list(self.customer_lookup)
        if self.sale_customer.get() not in self.customer_lookup: self.sale_customer.set('')

    def selected_customer_id(self):
        return self.customer_lookup.get(self.sale_customer.get())

    # ---------------- Version 8: credit book ----------------
    def make_credit(self):
        top=ttk.Frame(self.credit_tab); top.pack(fill='x')
        ttk.Button(top,text='Refresh credit book',command=self.refresh_credit).pack(side='left')
        ttk.Label(top,text='  Select an unpaid credit bill to record a payment.').pack(side='left')
        self.credit_tree=self.tree(self.credit_tab,('bill','customer','date','total','paid','balance'),(75,240,170,120,120,120))
        form=ttk.LabelFrame(self.credit_tab,text='Record payment against selected credit bill',padding=10); form.pack(fill='x')
        ttk.Label(form,text='Payment amount (Rs.)').pack(side='left')
        self.credit_amount=tk.StringVar()
        ttk.Entry(form,textvariable=self.credit_amount,width=15).pack(side='left',padx=8)
        ttk.Button(form,text='Record Payment',command=self.record_credit_payment).pack(side='left',padx=8)
        ttk.Button(form,text='View last payment receipt',command=self.view_credit_payment_receipt_v9).pack(side='left',padx=8)
        self.refresh_credit()

    def refresh_credit(self):
        if not hasattr(self,'credit_tree'): return
        self.credit_tree.delete(*self.credit_tree.get_children())
        with connection() as con:
            rows=con.execute("""SELECT s.id,c.name,s.created,s.total,
                  COALESCE((SELECT SUM(cp.amount) FROM credit_payments cp WHERE cp.sale_id=s.id),0) AS paid
                  FROM sales s JOIN customers c ON c.id=s.customer_id
                  WHERE s.payment_method='Credit' ORDER BY s.id DESC""").fetchall()
        for r in rows:
            self.credit_tree.insert('','end',values=(r['id'],r['name'],r['created'],f"{r['total']:.2f}",f"{r['paid']:.2f}",f"{max(0,r['total']-r['paid']):.2f}"))

    def record_credit_payment(self):
        selected=self.credit_tree.selection()
        if not selected:
            messagebox.showerror('Credit','Select a credit bill.'); return
        sale_id=int(self.credit_tree.item(selected[0],'values')[0])
        try:
            amount=round(finite_number(self.credit_amount.get(),'Payment amount',positive=True),2)
            if amount<=0: raise ValueError('Payment must be at least Rs. 0.01.')
            with connection() as con:
                con.execute('BEGIN IMMEDIATE')
                row=con.execute("""SELECT s.customer_id,s.total,
                     COALESCE((SELECT SUM(amount) FROM credit_payments WHERE sale_id=s.id),0) paid
                     FROM sales s WHERE s.id=? AND s.payment_method='Credit'""",(sale_id,)).fetchone()
                if not row: raise ValueError('Credit sale not found.')
                due=round(row['total']-row['paid'],2)
                if amount>due+0.001: raise ValueError(f'Payment exceeds remaining balance: {rupees(due)}')
                if not messagebox.askyesno('Confirm credit payment',f'Record {rupees(amount)} against Bill #{sale_id}?'):
                    return
                cur=con.execute('INSERT INTO credit_payments(sale_id,customer_id,amount,created,cashier) VALUES (?,?,?,?,?)',
                            (sale_id,row['customer_id'],amount,datetime.now().strftime('%Y-%m-%d %H:%M:%S'),self.user['username']))
                payment_id=cur.lastrowid
            self.last_credit_payment_id_v9=payment_id
            self.save_credit_payment_receipt_v9(payment_id)
            self.credit_amount.set(''); self.refresh_credit()
            messagebox.showinfo('Credit payment','Payment recorded successfully.')
        except (ValueError,sqlite3.Error) as exc: messagebox.showerror('Credit payment',str(exc))

    # ---------------- Version 8: printable Code39 labels ----------------
    def make_labels(self):
        ttk.Label(self.labels_tab,text='Create a printable barcode label for an existing product. Code 39 supports A-Z, 0-9, spaces and -.$/+%.').pack(anchor='w',pady=10)
        row=ttk.Frame(self.labels_tab); row.pack(fill='x')
        ttk.Label(row,text='Product barcode:').pack(side='left')
        self.label_barcode=tk.StringVar()
        ttk.Entry(row,textvariable=self.label_barcode,width=28).pack(side='left',padx=8)
        ttk.Button(row,text='Create Printable HTML Label',command=self.create_barcode_label).pack(side='left')
        ttk.Label(self.labels_tab,text='Open the generated HTML file in your browser and use Ctrl+P. Set paper size in printer settings.').pack(anchor='w',pady=12)

    def create_barcode_label(self):
        patterns={
          '0':'nnnwwnwnn','1':'wnnwnnnnw','2':'nnwwnnnnw','3':'wnwwnnnnn','4':'nnnwwnnnw',
          '5':'wnnwwnnnn','6':'nnwwwnnnn','7':'nnnwnnwnw','8':'wnnwnnwnn','9':'nnwwnnwnn',
          'A':'wnnnnwnnw','B':'nnwnnwnnw','C':'wnwnnwnnn','D':'nnnnwwnnw','E':'wnnnwwnnn',
          'F':'nnwnwwnnn','G':'nnnnnwwnw','H':'wnnnnwwnn','I':'nnwnnwwnn','J':'nnnnwwwnn',
          'K':'wnnnnnnww','L':'nnwnnnnww','M':'wnwnnnnwn','N':'nnnnwnnww','O':'wnnnwnnwn',
          'P':'nnwnwnnwn','Q':'nnnnnnwww','R':'wnnnnnwwn','S':'nnwnnnwwn','T':'nnnnwnwwn',
          'U':'wwnnnnnnw','V':'nwwnnnnnw','W':'wwwnnnnnn','X':'nwnnwnnnw','Y':'wwnnwnnnn',
          'Z':'nwwnwnnnn','-':'nwnnnnwnw','.':'wwnnnnwnn',' ':'nwwnnnwnn',
          '$':'nwnwnwnnn','/':'nwnwnnnwn','+':'nwnnnwnwn','%':'nnnwnwnwn','*':'nwnnwnwnn'}
        barcode=self.label_barcode.get().strip().upper()
        if not barcode or any(ch not in patterns or ch=='*' for ch in barcode):
            messagebox.showerror('Barcode','Code 39 only supports A-Z, 0-9, space and -.$/+%.'); return
        with connection() as con:
            product=con.execute('SELECT name,price FROM products WHERE barcode=?',(self.label_barcode.get().strip(),)).fetchone()
        if not product:
            messagebox.showerror('Barcode','Existing product barcode not found.'); return
        x=12; rects=[]
        for char in '*'+barcode+'*':
            for i,w in enumerate(patterns[char]):
                width=6 if w=='w' else 2
                if i%2==0: rects.append(f'<rect x="{x}" y="4" width="{width}" height="65" fill="black"/>')
                x+=width
            x+=2
        svg=f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {x+12} 75" width="100%" height="75">'+''.join(rects)+'</svg>'
        safe_name=xml_escape(product['name']); safe_bar=xml_escape(barcode)
        html=f"""<!doctype html><html><head><meta charset="utf-8"><title>Barcode Label</title>
<style>body{{font-family:Arial,sans-serif}}.label{{width:75mm;padding:3mm;text-align:center;border:1px dashed #aaa;box-sizing:border-box}}
@media print{{.label{{border:0}}@page{{margin:3mm}}}}</style></head><body><div class="label">
<strong>{safe_name}</strong><div>{svg}</div><div>{safe_bar}</div><strong>{rupees(product['price'])}</strong></div></body></html>"""
        folder=BASE/'barcode_labels'; folder.mkdir(exist_ok=True)
        path=folder/('label_'+''.join(c if c.isalnum() else '_' for c in barcode)+'.html')
        try:
            path.write_text(html,encoding='utf-8'); webbrowser.open(path.as_uri())
            messagebox.showinfo('Barcode label',f'Printable label created:\n{path}\n\nUse Ctrl+P in browser to print.')
        except OSError as exc: messagebox.showerror('Barcode label',str(exc))

    # ---------------- Version 8: Excel workbook ----------------
    def export_excel(self):
        try:
            from openpyxl import Workbook
            from openpyxl.styles import Font, PatternFill
        except ImportError:
            messagebox.showerror('Excel export','Install openpyxl first:\npy -m pip install openpyxl'); return
        path=filedialog.asksaveasfilename(title='Export Excel report',defaultextension='.xlsx',filetypes=[('Excel workbook','*.xlsx')])
        if not path: return
        try:
            wb=Workbook(); wb.remove(wb.active)
            queries={
                'Sales':'SELECT id,created,subtotal,discount,total,cashier,payment_method,customer_id FROM sales ORDER BY id',
                'Products':'SELECT id,barcode,name,price,cost,stock,unit,min_stock FROM products ORDER BY name',
                'Purchases':'SELECT * FROM purchases ORDER BY id',
                'Expenses':'SELECT * FROM expenses ORDER BY id',
                'Returns':'SELECT * FROM returns ORDER BY id',
                'Customers':'SELECT id,name,phone,address,created FROM customers ORDER BY id',
                'Credit Payments':'SELECT * FROM credit_payments ORDER BY id'}
            with connection() as con:
                for title,query in queries.items():
                    cursor=con.execute(query); ws=wb.create_sheet(title)
                    ws.append([d[0] for d in cursor.description])
                    for record in cursor: ws.append(list(record))
                    ws.freeze_panes='A2'; ws.auto_filter.ref=ws.dimensions
                    for cell in ws[1]:
                        cell.font=Font(bold=True,color='FFFFFF'); cell.fill=PatternFill('solid',fgColor='243B53')
                    for col in ws.columns:
                        letter=col[0].column_letter
                        ws.column_dimensions[letter].width=min(34,max(12,max(len(str(c.value or '')) for c in list(col)[:100])+2))
            wb.save(path); messagebox.showinfo('Excel export','Excel report saved successfully.')
        except (OSError,sqlite3.Error,ValueError) as exc: messagebox.showerror('Excel export',str(exc))

    # ---------------- Version 9: suppliers ----------------
    def make_suppliers_v9(self):
        ttk.Label(self.suppliers_tab,text='Supplier Management',font=('Segoe UI',16,'bold')).pack(anchor='w')
        bar=ttk.Frame(self.suppliers_tab); bar.pack(fill='x',pady=8)
        self.sup_v9={}
        for label,width in [('Name',25),('Phone',18),('Address',28),('Note',24)]:
            ttk.Label(bar,text=label).pack(side='left')
            v=tk.StringVar(); self.sup_v9[label]=v
            ttk.Entry(bar,textvariable=v,width=width).pack(side='left',padx=4)
        b=ttk.Button(self.suppliers_tab,text='Add / Update Supplier',command=self.save_supplier_v9); b.pack(anchor='w')
        if self.user['role']!='admin': b.state(['disabled'])
        self.sup_tree_v9=self.tree(self.suppliers_tab,('id','name','phone','address','note'),(55,220,160,270,230))
        self.sup_tree_v9.bind('<<TreeviewSelect>>',self.select_supplier_v9)
        self.refresh_suppliers_v9()

    def select_supplier_v9(self,event=None):
        selection=self.sup_tree_v9.selection()
        if selection:
            r=self.sup_tree_v9.item(selection[0],'values')
            for k,v in zip(('Name','Phone','Address','Note'),r[1:]): self.sup_v9[k].set(v)

    def save_supplier_v9(self):
        if self.user['role']!='admin': return
        name=self.sup_v9['Name'].get().strip()
        if not name: messagebox.showerror('Supplier','Enter supplier name.'); return
        if any(len(self.sup_v9[k].get())>200 for k in self.sup_v9):
            messagebox.showerror('Supplier','Field too long.'); return
        values=tuple(self.sup_v9[k].get().strip() for k in ('Name','Phone','Address','Note'))
        try:
            with connection() as con:
                con.execute('INSERT INTO suppliers_v9(name,phone,address,note) VALUES (?,?,?,?) ON CONFLICT(name) DO UPDATE SET phone=excluded.phone,address=excluded.address,note=excluded.note',values)
            self.refresh_suppliers_v9(); messagebox.showinfo('Supplier','Supplier saved.')
        except sqlite3.Error as e: messagebox.showerror('Supplier',str(e))

    def refresh_suppliers_v9(self):
        self.sup_tree_v9.delete(*self.sup_tree_v9.get_children())
        with connection() as con:
            for r in con.execute('SELECT * FROM suppliers_v9 ORDER BY name'):
                self.sup_tree_v9.insert('','end',values=tuple(r))

    # ---------------- Version 9: expiry batches ----------------
    def make_expiry_v9(self):
        ttk.Label(self.expiry_tab,text='Expiry Date Alerts (batch records)',font=('Segoe UI',16,'bold')).pack(anchor='w')
        ttk.Label(self.expiry_tab,text='Batch quantities are tracking information only. Receiving stock still happens in Stock Purchases.').pack(anchor='w')
        bar=ttk.Frame(self.expiry_tab); bar.pack(fill='x',pady=10)
        self.exp_v9={}
        for label,width in [('Barcode',17),('Batch',15),('Expiry YYYY-MM-DD',18),('Quantity',12)]:
            ttk.Label(bar,text=label).pack(side='left')
            v=tk.StringVar(); self.exp_v9[label]=v
            ttk.Entry(bar,textvariable=v,width=width).pack(side='left',padx=4)
        btn=ttk.Button(self.expiry_tab,text='Save batch',command=self.save_expiry_v9); btn.pack(anchor='w')
        if self.user['role']!='admin': btn.state(['disabled'])
        ttk.Label(self.expiry_tab,text='Show batches expiring within N days:').pack(anchor='w',pady=(10,0))
        self.exp_days_v9=tk.StringVar(value='30')
        row=ttk.Frame(self.expiry_tab); row.pack(anchor='w')
        ttk.Entry(row,textvariable=self.exp_days_v9,width=8).pack(side='left')
        ttk.Button(row,text='Refresh alerts',command=self.refresh_expiry_v9).pack(side='left',padx=6)
        self.exp_tree_v9=self.tree(self.expiry_tab,('product','barcode','batch','expiry','qty','status'),(230,145,150,140,95,160))
        self.refresh_expiry_v9()

    def save_expiry_v9(self):
        if self.user['role']!='admin': return
        try:
            barcode=self.exp_v9['Barcode'].get().strip(); batch=self.exp_v9['Batch'].get().strip()
            date=self.exp_v9['Expiry YYYY-MM-DD'].get().strip()
            if datetime.strptime(date,'%Y-%m-%d').strftime('%Y-%m-%d')!=date: raise ValueError('Use YYYY-MM-DD.')
            qty=finite_number(self.exp_v9['Quantity'].get(),'Batch quantity')
            if not barcode or not batch: raise ValueError('Barcode and batch are required.')
            with connection() as con:
                product=con.execute('SELECT id,unit FROM products WHERE barcode=?',(barcode,)).fetchone()
                if not product: raise ValueError('Product barcode not found.')
                if product['unit']=='pcs' and not qty.is_integer(): raise ValueError('pcs quantity must be whole.')
                con.execute('INSERT INTO expiry_batches_v9(product_id,batch_code,expiry_date,qty,created) VALUES (?,?,?,?,?) ON CONFLICT(product_id,batch_code,expiry_date) DO UPDATE SET qty=excluded.qty',
                    (product['id'],batch,date,qty,datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            self.refresh_expiry_v9(); messagebox.showinfo('Expiry','Batch record saved. Stock quantity was not changed.')
        except (ValueError,sqlite3.Error) as e: messagebox.showerror('Expiry',str(e))

    def refresh_expiry_v9(self):
        try:
            days=int(self.exp_days_v9.get())
            if not 0<=days<=3650: raise ValueError()
        except ValueError:
            messagebox.showerror('Expiry','Enter 0 to 3650 days.'); return
        today=datetime.now().date(); end=(today+timedelta(days=days)).isoformat()
        self.exp_tree_v9.delete(*self.exp_tree_v9.get_children())
        with connection() as con:
            rows=con.execute('''SELECT p.name,p.barcode,b.batch_code,b.expiry_date,b.qty FROM expiry_batches_v9 b JOIN products p ON p.id=b.product_id WHERE b.expiry_date<=? AND b.qty>0 ORDER BY b.expiry_date''',(end,)).fetchall()
        for r in rows:
            status='EXPIRED' if r['expiry_date']<today.isoformat() else 'EXPIRING SOON'
            self.exp_tree_v9.insert('','end',values=(r['name'],r['barcode'],r['batch_code'],r['expiry_date'],r['qty'],status))

    # ---------------- Version 9: daily cash ----------------
    def make_cash_v9(self):
        ttk.Label(self.cash_tab,text='Daily Cash Register',font=('Segoe UI',16,'bold')).pack(anchor='w')
        ttk.Label(self.cash_tab,text='Cash totals exclude Credit sales; include Cash credit collections. Refunds and expenses are subtracted as assumed cash outflows.').pack(anchor='w',pady=4)
        bar=ttk.Frame(self.cash_tab); bar.pack(fill='x',pady=10)
        self.cash_day_v9=tk.StringVar(value=datetime.now().date().isoformat())
        self.cash_open_v9=tk.StringVar(value='0'); self.cash_count_v9=tk.StringVar()
        for label,var in [('Day YYYY-MM-DD',self.cash_day_v9),('Opening cash',self.cash_open_v9),('Counted closing cash',self.cash_count_v9)]:
            ttk.Label(bar,text=label).pack(side='left',padx=3)
            ttk.Entry(bar,textvariable=var,width=14).pack(side='left',padx=4)
        ttk.Button(self.cash_tab,text='Save opening cash',command=self.save_opening_v9).pack(anchor='w')
        ttk.Button(self.cash_tab,text='Close day (count cash)',command=self.close_cash_v9).pack(anchor='w',pady=5)
        ttk.Button(self.cash_tab,text='Refresh cash summary',command=self.refresh_cash_v9).pack(anchor='w')
        self.cash_report_v9=tk.Text(self.cash_tab,height=17,font=('Consolas',11)); self.cash_report_v9.pack(fill='both',expand=True,pady=10)
        self.refresh_cash_v9()

    def cash_values_v9(self):
        day=self.cash_day_v9.get().strip()
        if datetime.strptime(day,'%Y-%m-%d').strftime('%Y-%m-%d')!=day: raise ValueError('Invalid date.')
        with connection() as con:
            row=con.execute('SELECT * FROM cash_register_v9 WHERE day=?',(day,)).fetchone()
            cash_sales=con.execute("SELECT COALESCE(SUM(total),0) FROM sales WHERE substr(created,1,10)=? AND payment_method='Cash'",(day,)).fetchone()[0]
            credit=con.execute('SELECT COALESCE(SUM(amount),0) FROM credit_payments WHERE substr(created,1,10)=?',(day,)).fetchone()[0]
            refunds=con.execute('SELECT COALESCE(SUM(refund),0) FROM returns WHERE substr(created,1,10)=?',(day,)).fetchone()[0]
            expenses=con.execute('SELECT COALESCE(SUM(amount),0) FROM expenses WHERE substr(created,1,10)=?',(day,)).fetchone()[0]
        opening=row['opening'] if row else 0
        return row,opening,cash_sales,credit,refunds,expenses,opening+cash_sales+credit-refunds-expenses

    def save_opening_v9(self):
        if self.user['role']!='admin': messagebox.showerror('Cash','Admin only.'); return
        try:
            day=self.cash_day_v9.get().strip(); datetime.strptime(day,'%Y-%m-%d')
            amount=round(finite_number(self.cash_open_v9.get(),'Opening cash'),2)
            with connection() as con:
                old=con.execute('SELECT * FROM cash_register_v9 WHERE day=?',(day,)).fetchone()
                if old: raise ValueError('Opening cash already recorded for this day. It cannot be overwritten.')
                con.execute('INSERT INTO cash_register_v9(day,opening,cashier) VALUES (?,?,?)',(day,amount,self.user['username']))
            self.refresh_cash_v9()
        except (ValueError,sqlite3.Error) as e: messagebox.showerror('Cash',str(e))

    def close_cash_v9(self):
        if self.user['role']!='admin': messagebox.showerror('Cash','Admin only.'); return
        try:
            row,*_=self.cash_values_v9()
            if not row: raise ValueError('Save opening cash first.')
            if row['closed_at']: raise ValueError('This day is already closed.')
            counted=round(finite_number(self.cash_count_v9.get(),'Counted cash'),2)
            if not messagebox.askyesno('Close cash day',f'Confirm counted cash {rupees(counted)}?'): return
            with connection() as con:
                con.execute('UPDATE cash_register_v9 SET counted=?,closed_at=?,cashier=? WHERE day=? AND closed_at IS NULL',
                    (counted,datetime.now().strftime('%Y-%m-%d %H:%M:%S'),self.user['username'],row['day']))
            self.refresh_cash_v9()
        except (ValueError,sqlite3.Error) as e: messagebox.showerror('Cash',str(e))

    def refresh_cash_v9(self):
        try:
            row,opening,sales,credit,refunds,expenses,expected=self.cash_values_v9()
            out=(f'DAY: {self.cash_day_v9.get()}\n\nOpening cash:      {rupees(opening)}\nCash sales:        {rupees(sales)}\nCredit collected:  {rupees(credit)}\n'
                 f'Refunds (assumed cash): -{rupees(refunds)}\nExpenses (assumed cash): -{rupees(expenses)}\n\nEXPECTED CASH:     {rupees(expected)}\n')
            if row and row['closed_at']:
                out+=f"\nCounted cash:      {rupees(row['counted'])}\nDifference:        {rupees(row['counted']-expected)}\nClosed at:         {row['closed_at']}\n"
            out+='\nNOTE: Credit payment methods, expense/refund payment methods are not stored in V8. Verify actual cash manually.\nHistorical changes after closing may change the expected amount.'
            self.cash_report_v9.config(state='normal'); self.cash_report_v9.delete('1.0','end'); self.cash_report_v9.insert('1.0',out); self.cash_report_v9.config(state='disabled')
        except ValueError as e: messagebox.showerror('Cash',str(e))

    # ---------------- Version 9: profit dashboard ----------------
    def make_profit_v9(self):
        ttk.Label(self.v9_dashboard_tab,text='Monthly Sales & Estimated Profit',font=('Segoe UI',16,'bold')).pack(anchor='w')
        ttk.Label(self.v9_dashboard_tab,text='Monthly view; credit sales included as sales (not cash). Profit uses stored item cost and is an estimate.').pack(anchor='w')
        ttk.Button(self.v9_dashboard_tab,text='Refresh chart',command=self.refresh_profit_v9).pack(anchor='w',pady=6)
        self.profit_summary_v9=ttk.Label(self.v9_dashboard_tab,text=''); self.profit_summary_v9.pack(anchor='w')
        self.profit_canvas_v9=tk.Canvas(self.v9_dashboard_tab,height=390,background='white'); self.profit_canvas_v9.pack(fill='both',expand=True,pady=10)
        self.refresh_profit_v9()

    def refresh_profit_v9(self):
        months=[(datetime.now().replace(day=1)-timedelta(days=1)).strftime('%Y-%m')]
        for _ in range(5): months.append((datetime.strptime(months[-1]+'-01','%Y-%m-%d')-timedelta(days=1)).strftime('%Y-%m'))
        months.reverse(); data=[]
        with connection() as con:
            for month in months:
                sales=con.execute('SELECT COALESCE(SUM(total),0) FROM sales WHERE substr(created,1,7)=?',(month,)).fetchone()[0]
                margin=con.execute('''SELECT COALESCE(SUM(si.total-si.qty*si.cost),0) FROM sale_items si JOIN sales s ON s.id=si.sale_id WHERE substr(s.created,1,7)=?''',(month,)).fetchone()[0]
                discount=con.execute('SELECT COALESCE(SUM(discount),0) FROM sales WHERE substr(created,1,7)=?',(month,)).fetchone()[0]
                refunds=con.execute('SELECT COALESCE(SUM(refund),0) FROM returns WHERE substr(created,1,7)=?',(month,)).fetchone()[0]
                returned_cost=con.execute('SELECT COALESCE(SUM(qty*cost),0) FROM returns WHERE substr(created,1,7)=?',(month,)).fetchone()[0]
                expenses=con.execute('SELECT COALESCE(SUM(amount),0) FROM expenses WHERE substr(created,1,7)=?',(month,)).fetchone()[0]
                data.append((month,float(sales),float(margin-discount-refunds+returned_cost-expenses)))
        self.profit_summary_v9.config(text='Current month: Sales '+rupees(data[-1][1])+' | Estimated profit after expenses '+rupees(data[-1][2]))
        self.profit_canvas_v9.delete('all'); c=self.profit_canvas_v9
        width=max(850,c.winfo_width()); height=max(350,c.winfo_height())
        vals=[abs(v) for _,a,b in data for v in (a,b)]; maximum=max(vals+[1]); mid=height-75; scale=(height-125)/maximum
        for i,(month,sale,profit) in enumerate(data):
            center=80+i*(width-140)/6; bw=24
            c.create_rectangle(center-bw,mid-sale*scale,center,mid,fill='#287fba',outline='')
            c.create_rectangle(center+5,min(mid,mid-profit*scale),center+5+bw,max(mid,mid-profit*scale),fill='#269d67' if profit>=0 else '#c0392b',outline='')
            c.create_text(center+2,mid+20,text=month,anchor='center',font=('Segoe UI',9))
        c.create_text(15,15,text='Blue: Sales    Green: Profit    Red: Loss',anchor='w')
        c.create_line(30,mid,width-30,mid,fill='#555')

    # ---------------- Version 9: credit payment receipts ----------------
    def save_credit_payment_receipt_v9(self,payment_id):
        with connection() as con:
            r=con.execute('''SELECT cp.*,c.name AS customer_name,s.total AS sale_total,
                 (SELECT COALESCE(SUM(amount),0) FROM credit_payments WHERE sale_id=cp.sale_id AND id<=cp.id) AS paid_through
                 FROM credit_payments cp JOIN customers c ON c.id=cp.customer_id
                 JOIN sales s ON s.id=cp.sale_id WHERE cp.id=?''',(payment_id,)).fetchone()
        if not r: raise ValueError('Payment not found.')
        content=(f'{self.shop_name()}\nCREDIT PAYMENT RECEIPT\n'+('-'*42)+'\n'
                 f"Receipt #: CP-{r['id']}\nDate: {r['created']}\nCustomer: {r['customer_name']}\nBill #: {r['sale_id']}\n"
                 f"Payment received: {rupees(r['amount'])}\nBalance after payment: {rupees(max(0,r['sale_total']-r['paid_through']))}\n"
                 f"Cashier: {r['cashier']}\n"+('-'*42)+'\nThank you!')
        RECEIPTS.mkdir(exist_ok=True)
        path=RECEIPTS/f"credit_payment_{payment_id}.txt"; path.write_text(content,encoding='utf-8')
        self.last_credit_receipt_v9=content
        return content

    def view_credit_payment_receipt_v9(self):
        if hasattr(self,'last_credit_receipt_v9'): self.show_receipt(self.last_credit_receipt_v9)
        else: messagebox.showinfo('Credit receipt','Record a payment first. Previous payment receipts are saved in receipts folder.')

    # ---------------- Version 9: safe restore ----------------
    def make_restore_v9(self):
        ttk.Label(self.restore_tab,text='Database Backup & Restore (Admin)',font=('Segoe UI',16,'bold')).pack(anchor='w')
        ttk.Label(self.restore_tab,text='Restore creates a NEW database file for manual replacement while the app is CLOSED. Never overwrites live grocery.db.').pack(anchor='w',pady=10)
        ttk.Button(self.restore_tab,text='Create backup now',command=self.backup_database).pack(anchor='w',pady=5)
        btn=ttk.Button(self.restore_tab,text='Validate backup and prepare restored copy',command=self.prepare_restore_v9); btn.pack(anchor='w',pady=5)
        if self.user['role']!='admin': btn.state(['disabled'])
        ttk.Label(self.restore_tab,text='After preparation: close application, back up existing grocery.db, then manually replace only if you are certain.\nRestoring an older snapshot loses transactions created after that backup.',foreground='#8b2525').pack(anchor='w',pady=10)

    def prepare_restore_v9(self):
        if self.user['role']!='admin': return
        source=filedialog.askopenfilename(title='Select SQLite backup to validate',filetypes=[('SQLite database','*.db'),('All files','*.*')])
        if not source: return
        target=BACKUPS/('restore_prepared_'+datetime.now().strftime('%Y%m%d_%H%M%S_%f')+'.db')
        try:
            if Path(source).resolve()==DB.resolve(): raise ValueError('Select a backup, not the live grocery.db.')
            with closing(sqlite3.connect(f'file:{Path(source).resolve().as_posix()}?mode=ro',uri=True)) as src:
                if src.execute('PRAGMA integrity_check').fetchone()[0]!='ok': raise ValueError('Backup integrity check failed.')
                tables={r[0] for r in src.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if not {'users','products','sales','sale_items','settings'}.issubset(tables): raise ValueError('Not a valid grocery billing backup.')
                BACKUPS.mkdir(exist_ok=True)
                with closing(sqlite3.connect(str(target))) as dst: src.backup(dst)
            with closing(sqlite3.connect(str(target))) as verify:
                if verify.execute('PRAGMA integrity_check').fetchone()[0]!='ok': raise ValueError('Prepared copy failed integrity check.')
            messagebox.showinfo('Restore copy prepared',f'Validated backup and created:\n{target}\n\nLIVE grocery.db IS UNCHANGED.\nClose app before any manual replacement.')
        except (ValueError,sqlite3.Error,OSError) as e: messagebox.showerror('Restore',str(e))

    # ---------------- Version 10: purchase orders ----------------
    def make_orders_v10(self):
        ttk.Label(self.orders_tab_v10,text='Purchase Orders (orders do not change stock)',font=('Segoe UI',15,'bold')).pack(anchor='w')
        bar=ttk.Frame(self.orders_tab_v10); bar.pack(fill='x',pady=8)
        self.po_supplier_v10=tk.StringVar(); self.po_barcode_v10=tk.StringVar(); self.po_qty_v10=tk.StringVar(); self.po_cost_v10=tk.StringVar()
        for label,var,w in [('Supplier name',self.po_supplier_v10,23),('Product barcode',self.po_barcode_v10,17),('Quantity',self.po_qty_v10,10),('Unit cost',self.po_cost_v10,12)]:
            ttk.Label(bar,text=label).pack(side='left'); ttk.Entry(bar,textvariable=var,width=w).pack(side='left',padx=4)
        ttk.Button(self.orders_tab_v10,text='Create Purchase Order',command=self.add_order_v10).pack(anchor='w')
        ttk.Button(self.orders_tab_v10,text='Mark selected RECEIVED (no stock change; use Stock Purchases to add stock)',command=self.receive_order_v10).pack(anchor='w',pady=5)
        self.po_tree_v10=self.tree(self.orders_tab_v10,('id','date','supplier','product','qty','unit_cost','status'),(50,160,200,240,80,100,115))
        self.refresh_orders_v10()

    def add_order_v10(self):
        if self.user['role']!='admin': messagebox.showerror('Orders','Admin only.'); return
        try:
            supplier=self.po_supplier_v10.get().strip(); barcode=self.po_barcode_v10.get().strip()
            qty=finite_number(self.po_qty_v10.get(),'Quantity',positive=True); cost=finite_number(self.po_cost_v10.get(),'Unit cost')
            with connection() as con:
                con.execute('BEGIN IMMEDIATE')
                p=con.execute('SELECT * FROM products WHERE barcode=?',(barcode,)).fetchone()
                s=con.execute('SELECT id FROM suppliers_v9 WHERE name=?',(supplier,)).fetchone()
                if not p or not s: raise ValueError('Select an existing product barcode and exact supplier name from Suppliers V9.')
                if p['unit']=='pcs' and not qty.is_integer(): raise ValueError('Pcs quantity must be a whole number.')
                con.execute('INSERT INTO purchase_orders_v10(created,supplier_id,product_id,qty,unit_cost,status,cashier) VALUES (?,?,?,?,?,?,?)',
                    (datetime.now().strftime('%Y-%m-%d %H:%M:%S'),s['id'],p['id'],qty,round(cost,2),'ORDERED',self.user['username']))
            self.refresh_orders_v10(); messagebox.showinfo('Orders','Purchase order created. Stock has NOT changed.')
        except (ValueError,sqlite3.Error) as e: messagebox.showerror('Orders',str(e))

    def receive_order_v10(self):
        if self.user['role']!='admin': return
        chosen=self.po_tree_v10.selection()
        if not chosen: return
        oid=int(self.po_tree_v10.item(chosen[0],'values')[0])
        if not messagebox.askyesno('Order status','Mark this order received? This does NOT update stock. Use Stock Purchases to record actual delivery.'): return
        with connection() as con:
            result=con.execute("UPDATE purchase_orders_v10 SET status='RECEIVED' WHERE id=? AND status='ORDERED'",(oid,))
        if result.rowcount!=1: messagebox.showwarning('Orders','Order was already received.')
        self.refresh_orders_v10()

    def refresh_orders_v10(self):
        self.po_tree_v10.delete(*self.po_tree_v10.get_children())
        with connection() as con:
            rows=con.execute('''SELECT po.*,s.name supplier,p.name product FROM purchase_orders_v10 po
              JOIN suppliers_v9 s ON s.id=po.supplier_id JOIN products p ON p.id=po.product_id ORDER BY po.id DESC''').fetchall()
        for r in rows: self.po_tree_v10.insert('','end',values=(r['id'],r['created'],r['supplier'],r['product'],f"{r['qty']:g}",f"{r['unit_cost']:.2f}",r['status']))

    # ---------------- Version 10: stock adjustments ----------------
    def make_adjustments_v10(self):
        ttk.Label(self.adjust_tab_v10,text='Stock Adjustments - Admin only / audited',font=('Segoe UI',15,'bold')).pack(anchor='w')
        bar=ttk.Frame(self.adjust_tab_v10); bar.pack(fill='x',pady=8)
        self.adj_barcode_v10=tk.StringVar(); self.adj_delta_v10=tk.StringVar(); self.adj_reason_v10=tk.StringVar()
        for label,var,w in [('Barcode',self.adj_barcode_v10,18),('Change (+/- quantity)',self.adj_delta_v10,16),('Reason',self.adj_reason_v10,35)]:
            ttk.Label(bar,text=label).pack(side='left'); ttk.Entry(bar,textvariable=var,width=w).pack(side='left',padx=5)
        ttk.Button(self.adjust_tab_v10,text='Apply adjustment',command=self.apply_adjustment_v10).pack(anchor='w')
        self.adj_tree_v10=self.tree(self.adjust_tab_v10,('id','date','product','change','before','after','reason','cashier'),(45,160,200,80,80,80,220,100))
        self.refresh_adjustments_v10()

    def apply_adjustment_v10(self):
        if self.user['role']!='admin': messagebox.showerror('Stock','Admin only.'); return
        try:
            barcode=self.adj_barcode_v10.get().strip(); reason=self.adj_reason_v10.get().strip()
            delta=float(self.adj_delta_v10.get())
            if not math.isfinite(delta) or abs(delta)<1e-9 or not reason: raise ValueError('Enter nonzero change and reason.')
            with connection() as con:
                con.execute('BEGIN IMMEDIATE')
                p=con.execute('SELECT * FROM products WHERE barcode=?',(barcode,)).fetchone()
                if not p: raise ValueError('Product not found.')
                if p['unit']=='pcs' and not delta.is_integer(): raise ValueError('Pcs changes must be whole numbers.')
                after=round(p['stock']+delta,5)
                if after<0: raise ValueError('Adjustment cannot make stock negative.')
                if not messagebox.askyesno('Confirm stock adjustment',f"{p['name']}: {p['stock']:g} -> {after:g} {p['unit']}?\nReason: {reason}"): return
                con.execute('UPDATE products SET stock=? WHERE id=?',(after,p['id']))
                con.execute('INSERT INTO stock_adjustments_v10(created,product_id,delta,before_qty,after_qty,reason,cashier) VALUES (?,?,?,?,?,?,?)',
                    (datetime.now().strftime('%Y-%m-%d %H:%M:%S'),p['id'],delta,p['stock'],after,reason,self.user['username']))
            self.refresh_adjustments_v10(); self.refresh_products(); messagebox.showinfo('Stock','Stock adjusted and audit recorded.')
        except (ValueError,sqlite3.Error) as e: messagebox.showerror('Stock',str(e))

    def refresh_adjustments_v10(self):
        self.adj_tree_v10.delete(*self.adj_tree_v10.get_children())
        with connection() as con:
            rows=con.execute('SELECT a.*,p.name product FROM stock_adjustments_v10 a JOIN products p ON p.id=a.product_id ORDER BY a.id DESC LIMIT 500').fetchall()
        for r in rows: self.adj_tree_v10.insert('','end',values=(r['id'],r['created'],r['product'],f"{r['delta']:g}",f"{r['before_qty']:g}",f"{r['after_qty']:g}",r['reason'],r['cashier']))

    # ---------------- Version 10: customer statements ----------------
    def make_statements_v10(self):
        ttk.Label(self.statement_tab_v10,text='Customer Credit Statement',font=('Segoe UI',15,'bold')).pack(anchor='w')
        bar=ttk.Frame(self.statement_tab_v10); bar.pack(fill='x',pady=8)
        ttk.Label(bar,text='Customer ID (from Customers tab)').pack(side='left')
        self.statement_customer_v10=tk.StringVar(); ttk.Entry(bar,textvariable=self.statement_customer_v10,width=12).pack(side='left',padx=6)
        ttk.Button(bar,text='Show Statement',command=self.refresh_statement_v10).pack(side='left')
        ttk.Button(bar,text='Save Statement TXT',command=self.save_statement_v10).pack(side='left',padx=8)
        self.statement_text_v10=tk.Text(self.statement_tab_v10,font=('Consolas',11)); self.statement_text_v10.pack(fill='both',expand=True,pady=8)

    def statement_content_v10(self):
        try: cid=int(self.statement_customer_v10.get())
        except ValueError: raise ValueError('Enter numeric Customer ID from Customers tab.')
        with connection() as con:
            customer=con.execute('SELECT * FROM customers WHERE id=?',(cid,)).fetchone()
            if not customer: raise ValueError('Customer not found.')
            sales=con.execute("SELECT id,created,total FROM sales WHERE customer_id=? AND payment_method='Credit' ORDER BY created,id",(cid,)).fetchall()
            payments=con.execute('SELECT id,sale_id,created,amount FROM credit_payments WHERE customer_id=? ORDER BY created,id',(cid,)).fetchall()
        events=[(r['created'],0,r['id'],float(r['total']),f"Credit bill #{r['id']}") for r in sales]
        events += [(r['created'],1,r['id'],-float(r['amount']),f"Payment #{r['id']} for bill #{r['sale_id']}") for r in payments]
        events.sort()
        running=0.0; lines=[self.shop_name(),'CUSTOMER CREDIT STATEMENT',f"Customer: {customer['name']} (ID {cid})",'-'*75]
        for date,_,_,amount,desc in events:
            running+=amount; lines.append(f'{date} | {desc:32.32} | {amount:>11,.2f} | {running:>11,.2f}')
        lines.extend(['-'*75,f'OUTSTANDING CREDIT: {rupees(running)}','Note: refunds are not offset against credit balances in the current credit ledger.'])
        return '\n'.join(lines)

    def refresh_statement_v10(self):
        try:
            content=self.statement_content_v10(); self.statement_text_v10.delete('1.0','end'); self.statement_text_v10.insert('1.0',content)
        except (ValueError,sqlite3.Error) as e: messagebox.showerror('Statement',str(e))

    def save_statement_v10(self):
        try: content=self.statement_content_v10()
        except (ValueError,sqlite3.Error) as e: messagebox.showerror('Statement',str(e)); return
        path=filedialog.asksaveasfilename(defaultextension='.txt',filetypes=[('Text','*.txt')],initialfile='customer_statement_'+self.statement_customer_v10.get()+'.txt')
        if path:
            try: Path(path).write_text(content,encoding='utf-8'); messagebox.showinfo('Statement','Saved.')
            except OSError as e: messagebox.showerror('Statement',str(e))

    # ---------------- Version 10: cashier shift tracking ----------------
    def make_shifts_v10(self):
        ttk.Label(self.shift_tab_v10,text='Cashier Shift Register',font=('Segoe UI',15,'bold')).pack(anchor='w')
        ttk.Label(self.shift_tab_v10,text='Sales totals are for the signed-in cashier; credit collections are not assigned to a shift automatically.').pack(anchor='w')
        bar=ttk.Frame(self.shift_tab_v10); bar.pack(fill='x',pady=8)
        self.shift_open_v10=tk.StringVar(value='0'); self.shift_count_v10=tk.StringVar()
        for label,var in [('Opening cash',self.shift_open_v10),('Counted cash at close',self.shift_count_v10)]:
            ttk.Label(bar,text=label).pack(side='left'); ttk.Entry(bar,textvariable=var,width=16).pack(side='left',padx=8)
        ttk.Button(self.shift_tab_v10,text='Start shift',command=self.start_shift_v10).pack(anchor='w')
        ttk.Button(self.shift_tab_v10,text='Close active shift',command=self.close_shift_v10).pack(anchor='w',pady=5)
        self.shift_tree_v10=self.tree(self.shift_tab_v10,('id','cashier','started','ended','opening','cash_sales','counted'),(55,110,175,175,110,110,110))
        self.refresh_shifts_v10()

    def start_shift_v10(self):
        try:
            opening=round(finite_number(self.shift_open_v10.get(),'Opening cash'),2)
            with connection() as con:
                con.execute('BEGIN IMMEDIATE')
                if con.execute('SELECT 1 FROM cashier_shifts_v10 WHERE cashier=? AND ended IS NULL',(self.user['username'],)).fetchone(): raise ValueError('Close your active shift first.')
                con.execute('INSERT INTO cashier_shifts_v10(cashier,started,opening) VALUES (?,?,?)',(self.user['username'],datetime.now().strftime('%Y-%m-%d %H:%M:%S'),opening))
            self.refresh_shifts_v10(); messagebox.showinfo('Shift','Shift started.')
        except (ValueError,sqlite3.Error) as e: messagebox.showerror('Shift',str(e))

    def close_shift_v10(self):
        try:
            counted=round(finite_number(self.shift_count_v10.get(),'Counted cash'),2)
            with connection() as con:
                con.execute('BEGIN IMMEDIATE')
                r=con.execute('SELECT * FROM cashier_shifts_v10 WHERE cashier=? AND ended IS NULL',(self.user['username'],)).fetchone()
                if not r: raise ValueError('No active shift.')
                end=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                cash=con.execute("SELECT COALESCE(SUM(total),0) FROM sales WHERE cashier=? AND payment_method='Cash' AND created>=? AND created<=?",(self.user['username'],r['started'],end)).fetchone()[0]
                if not messagebox.askyesno('Close shift',f'Cash sales: {rupees(cash)}\nExpected before refunds/expenses: {rupees(r["opening"]+cash)}\nCounted: {rupees(counted)}\nClose shift?'): return
                con.execute('UPDATE cashier_shifts_v10 SET ended=?,cash_sales=?,counted=? WHERE id=?',(end,cash,counted,r['id']))
            self.refresh_shifts_v10()
        except (ValueError,sqlite3.Error) as e: messagebox.showerror('Shift',str(e))

    def refresh_shifts_v10(self):
        self.shift_tree_v10.delete(*self.shift_tree_v10.get_children())
        with connection() as con:
            rows=con.execute('SELECT * FROM cashier_shifts_v10 ORDER BY id DESC LIMIT 200').fetchall()
        for r in rows: self.shift_tree_v10.insert('','end',values=(r['id'],r['cashier'],r['started'],r['ended'] or 'ACTIVE',f"{r['opening']:.2f}",'' if r['cash_sales'] is None else f"{r['cash_sales']:.2f}",'' if r['counted'] is None else f"{r['counted']:.2f}"))

    # ---------------- Version 10: product categories ----------------
    def make_categories_v10(self):
        ttk.Label(self.category_tab_v10,text='Product Categories',font=('Segoe UI',15,'bold')).pack(anchor='w')
        bar=ttk.Frame(self.category_tab_v10); bar.pack(fill='x',pady=8)
        self.cat_name_v10=tk.StringVar(); self.cat_barcode_v10=tk.StringVar(); self.cat_assign_v10=tk.StringVar()
        ttk.Label(bar,text='New category').pack(side='left'); ttk.Entry(bar,textvariable=self.cat_name_v10,width=23).pack(side='left',padx=5)
        ttk.Button(bar,text='Add Category',command=self.add_category_v10).pack(side='left')
        line=ttk.Frame(self.category_tab_v10); line.pack(fill='x',pady=8)
        ttk.Label(line,text='Product barcode').pack(side='left'); ttk.Entry(line,textvariable=self.cat_barcode_v10,width=20).pack(side='left',padx=5)
        ttk.Label(line,text='Category name').pack(side='left'); ttk.Entry(line,textvariable=self.cat_assign_v10,width=23).pack(side='left',padx=5)
        ttk.Button(line,text='Assign Category',command=self.assign_category_v10).pack(side='left')
        self.category_tree_v10=self.tree(self.category_tab_v10,('barcode','product','category'),(180,360,250))
        self.refresh_categories_v10()

    def add_category_v10(self):
        if self.user['role']!='admin': messagebox.showerror('Categories','Admin only.'); return
        name=self.cat_name_v10.get().strip()
        if not name: messagebox.showerror('Categories','Enter a name.'); return
        with connection() as con: con.execute('INSERT OR IGNORE INTO product_categories_v10(name) VALUES (?)',(name,))
        self.refresh_categories_v10(); messagebox.showinfo('Categories','Category saved.')

    def assign_category_v10(self):
        if self.user['role']!='admin': messagebox.showerror('Categories','Admin only.'); return
        with connection() as con:
            cat=con.execute('SELECT id FROM product_categories_v10 WHERE name=?',(self.cat_assign_v10.get().strip(),)).fetchone()
            if not cat: messagebox.showerror('Categories','Create the category first; name must match.'); return
            result=con.execute('UPDATE products SET category_id_v10=? WHERE barcode=?',(cat['id'],self.cat_barcode_v10.get().strip()))
        if not result.rowcount: messagebox.showerror('Categories','Product barcode not found.')
        self.refresh_categories_v10()

    def refresh_categories_v10(self):
        self.category_tree_v10.delete(*self.category_tree_v10.get_children())
        with connection() as con:
            rows=con.execute('SELECT p.barcode,p.name,COALESCE(c.name,\'Uncategorized\') category FROM products p LEFT JOIN product_categories_v10 c ON c.id=p.category_id_v10 ORDER BY p.name').fetchall()
        for r in rows: self.category_tree_v10.insert('','end',values=(r['barcode'],r['name'],r['category']))

    # ---------------- Version 10: business reporting ----------------
    def make_business_reports_v10(self):
        ttk.Label(self.business_tab_v10,text='Daily / Weekly / Monthly Business Reports',font=('Segoe UI',15,'bold')).pack(anchor='w')
        bar=ttk.Frame(self.business_tab_v10); bar.pack(fill='x',pady=8)
        self.business_period_v10=tk.StringVar(value='Daily')
        ttk.Combobox(bar,textvariable=self.business_period_v10,values=('Daily','Weekly','Monthly'),state='readonly',width=14).pack(side='left',padx=5)
        ttk.Button(bar,text='Refresh',command=self.refresh_business_v10).pack(side='left')
        ttk.Button(bar,text='Export CSV',command=self.export_business_v10).pack(side='left',padx=8)
        self.business_tree_v10=self.tree(self.business_tab_v10,('period','bills','sales','refunds','expenses','estimated_profit'),(190,80,140,140,140,160))
        self.refresh_business_v10()

    def business_rows_v10(self):
        period=self.business_period_v10.get()
        if period=='Daily': fmt="substr(created,1,10)"
        elif period=='Weekly': fmt="strftime('%Y-W%W',created)"
        else: fmt="substr(created,1,7)"
        with connection() as con:
            sales=con.execute(f'''SELECT {fmt} period,COUNT(*) bills,SUM(total) sales,SUM(discount) discounts
                FROM sales GROUP BY period ORDER BY period DESC''').fetchall()
            itemprofits=con.execute(f'''SELECT {fmt.replace('created','s.created')} period,
                SUM(si.total-si.cost*si.qty) gross FROM sale_items si JOIN sales s ON s.id=si.sale_id GROUP BY period''').fetchall()
            refunds=con.execute(f'SELECT {fmt} period,SUM(refund-cost*qty) effect,SUM(refund) amount FROM returns GROUP BY period').fetchall()
            expenses=con.execute(f'SELECT {fmt} period,SUM(amount) amount FROM expenses GROUP BY period').fetchall()
        gross={r['period']:r['gross'] or 0 for r in itemprofits}; ref={r['period']:r for r in refunds}; exp={r['period']:r['amount'] or 0 for r in expenses}
        return [(r['period'],r['bills'],round(r['sales'] or 0,2),round(ref[r['period']]['amount'],2) if r['period'] in ref else 0,round(exp.get(r['period'],0),2),round(gross.get(r['period'],0)-(r['discounts'] or 0)-(ref[r['period']]['effect'] if r['period'] in ref else 0)-exp.get(r['period'],0),2)) for r in sales]

    def refresh_business_v10(self):
        self.business_tree_v10.delete(*self.business_tree_v10.get_children())
        for r in self.business_rows_v10(): self.business_tree_v10.insert('','end',values=r)

    def export_business_v10(self):
        path=filedialog.asksaveasfilename(defaultextension='.csv',filetypes=[('CSV','*.csv')])
        if not path: return
        try:
            with open(path,'w',newline='',encoding='utf-8-sig') as f:
                writer=csv.writer(f); writer.writerow(['Period','Bills','Gross Sales LKR','Refunds LKR','Expenses LKR','Estimated Profit LKR']); writer.writerows(self.business_rows_v10())
            messagebox.showinfo('Reports','CSV exported.')
        except (OSError,sqlite3.Error) as e: messagebox.showerror('Reports',str(e))

if __name__ == '__main__':
    root = tk.Tk()
    root.withdraw()
    try:
        automatic_backup()
    except (OSError,sqlite3.Error) as exc:
        messagebox.showwarning('Automatic backup', 'Automatic backup failed: '+str(exc)+'\nUse Sales / Reports > Backup database manually.')
    while True:
        user = login_or_setup(root)
        if user is None:
            break
        window = tk.Toplevel(root)
        App(window, user)
        window.protocol('WM_DELETE_WINDOW', window.destroy)
        root.wait_window(window)
    root.destroy()
