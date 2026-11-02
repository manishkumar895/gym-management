# Form / Function - Gym Management

A beginner-friendly gym member management website built with Flask, SQLite, HTML, CSS, and JavaScript.

## Features

- Dashboard with total and active member counts
- Add a member with personal and membership details
- View the member directory
- Edit member details and view a member profile
- Search members by name, phone, email, or membership plan
- Admin login with a hashed password and session-protected management pages
- Optional demo mode for showing management pages without logging in
- Record payments and view gym-wide or per-member payment history
- View and print payment receipts, with browser print-to-PDF support
- Record membership duration and start/expiry dates with each payment
- Calculate expiry status and show Paid, Due Soon, Due Today, or Overdue
- Filter due fees and prepare a copyable reminder message without sending externally
- Reminder center with 7-day, 3-day, 1-day, expiry-day, and expired-membership message templates
- Download a consistent SQLite database backup from the authenticated navigation
- Dashboard payment totals, recent payments, fee counts, and outstanding fees
- Automatic SQLite database and table creation
- Responsive sidebar and layout

## Requirements

- Python 3.10 or newer
- pip
- A web browser

## Install and run

Open a terminal in this folder and run:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

If PowerShell blocks virtual-environment activation, run `python -m pip install -r requirements.txt` with your selected Python installation instead.

Open <http://127.0.0.1:5000> in your browser. The `database.db` file is created automatically beside `app.py` the first time the application starts.

Local development starts with authentication disabled so the dashboard opens directly at <http://127.0.0.1:5000/>. The login page and admin credentials remain available; set `DEMO_MODE=0` to require login. The default local development admin credentials are `admin` / `admin123`. Set `ADMIN_USERNAME` and `ADMIN_PASSWORD` in the environment to configure the account; the configured credentials are stored in the admins table as a Werkzeug password hash.

**Security warning:** Local development mode allows unauthenticated access to member, payment, and database backup pages. Do not expose this application publicly or use this mode with real member data. Before deployment, set `DEMO_MODE=0`, configure a private `SECRET_KEY` and strong admin credentials, disable debug mode, and use a production WSGI server.

## Project structure

```text
gym_management/
├── app.py
├── database.db          # created automatically on first run; use Database backup to download a copy
├── requirements.txt
├── README.md
├── templates/
│   ├── base.html
│   ├── dashboard.html
│   ├── members.html
│   ├── add_member.html
│   ├── edit_member.html
│   ├── member_profile.html
│   ├── add_payment.html
│   ├── payments.html
│   ├── payment_history.html
│   ├── due_fees.html
│   ├── reminder_center.html
│   └── 404.html
├── static/
│   ├── css/style.css
│   └── js/script.js
└── tests/
    └── test_payment_routes.py
```

## Run tests

```powershell
python -m unittest discover -s tests -v
```

## Notes

- Data is stored locally in SQLite. Payment rows reference a member with a foreign key; deactivating a member does not remove payment history.
- Fee status is calculated from each member's saved membership expiry date. Recording a payment saves the payment period and updates the member's current membership start and expiry dates; dates 1-7 days away are Due Soon, the current date is Due Today, and past dates are Overdue. Later dates are Paid.
- Dashboard outstanding fees sum the monthly fees for active members whose fees are due today or overdue. Reminder actions only prepare a message and do not contact an external service or create payment records.
- The Reminder Center uses each active member's saved expiry date, lists each member once, and provides a copyable template for memberships expiring within 7 days or already expired.
- The app uses parameterized SQL statements and validates submitted form data on the server. Payment forms use a one-time submission token so refreshing or replaying a successful form does not create a duplicate payment.
- Admin sessions use HTTP-only, SameSite=Lax cookies and expire after eight hours. Set a private, stable `SECRET_KEY` in the environment for deployments; when it is not set, the app creates and reuses a random key in `instance/secret_key` so sessions remain valid across local server restarts. Keep this key private and do not delete it while logged-in sessions should remain valid. Set `SESSION_COOKIE_SECURE=1` when serving over HTTPS.
- The development server is for local learning. Before deploying publicly, set a private `SECRET_KEY`, disable debug mode, and use a production WSGI server.