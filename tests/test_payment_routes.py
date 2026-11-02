import tempfile
import unittest
import sqlite3
from unittest.mock import patch
from datetime import date, timedelta
from pathlib import Path
import re

import app as gym_app


class PaymentRouteTests(unittest.TestCase):
    def test_session_secret_persists_and_configured_key_takes_precedence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            secret_path = Path(temp_dir) / "instance" / "secret_key"
            first_key = gym_app.load_secret_key(secret_path)
            second_key = gym_app.load_secret_key(secret_path)

        self.assertEqual(first_key, second_key)
        self.assertEqual(len(first_key), 64)

        with patch.dict("os.environ", {"SECRET_KEY": "configured-test-key"}):
            self.assertEqual(
                gym_app.load_secret_key(Path("unused-secret-key")),
                "configured-test-key",
            )

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "test_gym.db"
        gym_app.DATABASE = self.database_path
        gym_app.app.config["TESTING"] = True
        gym_app.app.config["DEMO_MODE"] = False
        gym_app.app.config["ADMIN_CREDENTIALS_CONFIGURED"] = False
        gym_app.init_db()
        self.client = gym_app.app.test_client()
        login_response = self.client.post(
            "/login", data={"username": "admin", "password": "admin123"}
        )
        self.assertEqual(login_response.status_code, 302)
        self.addCleanup(self.temp_dir.cleanup)

    def test_admin_login_validation_and_password_hash(self):
        anonymous_client = gym_app.app.test_client()
        login_page = anonymous_client.get("/login")
        self.assertEqual(login_page.status_code, 200)
        self.assertIn(b"Username", login_page.data)
        self.assertIn(b"Password", login_page.data)
        self.assertNotIn(b"admin123", login_page.data)

        empty_login = anonymous_client.post(
            "/login", data={"username": "", "password": ""}
        )
        self.assertEqual(empty_login.status_code, 200)
        self.assertIn(b"Username and password are required", empty_login.data)

        wrong_password = anonymous_client.post(
            "/login", data={"username": "admin", "password": "wrong"}
        )
        self.assertEqual(wrong_password.status_code, 200)
        self.assertIn(b"Invalid username or password", wrong_password.data)
        self.assertEqual(anonymous_client.get("/members").status_code, 302)

        correct_login = anonymous_client.post(
            "/login", data={"username": "admin", "password": "admin123"}
        )
        self.assertEqual(correct_login.status_code, 302)
        self.assertEqual(anonymous_client.get("/dashboard").status_code, 200)

        with gym_app.get_db_connection() as connection:
            admin = connection.execute(
                "SELECT username, password_hash FROM admins WHERE username = ?",
                ("admin",),
            ).fetchone()
        self.assertNotEqual(admin["password_hash"], "admin123")
        self.assertTrue(
            gym_app.check_password_hash(admin["password_hash"], "admin123")
        )

    def test_admin_credentials_can_be_changed_through_configuration(self):
        original_username = gym_app.app.config["ADMIN_USERNAME"]
        original_password = gym_app.app.config["ADMIN_PASSWORD"]
        original_credentials_configured = gym_app.app.config[
            "ADMIN_CREDENTIALS_CONFIGURED"
        ]
        try:
            gym_app.app.config["ADMIN_USERNAME"] = "gym-owner"
            gym_app.app.config["ADMIN_PASSWORD"] = "changed-development-password"
            gym_app.app.config["ADMIN_CREDENTIALS_CONFIGURED"] = True
            gym_app.init_db()

            client = gym_app.app.test_client()
            response = client.post(
                "/login",
                data={
                    "username": "gym-owner",
                    "password": "changed-development-password",
                },
            )
            self.assertEqual(response.status_code, 302)
            self.assertEqual(client.get("/dashboard").status_code, 200)

            with gym_app.get_db_connection() as connection:
                admin = connection.execute(
                    "SELECT username, password_hash FROM admins"
                ).fetchone()
            self.assertEqual(admin["username"], "gym-owner")
            self.assertNotEqual(
                admin["password_hash"], "changed-development-password"
            )
            self.assertTrue(
                gym_app.check_password_hash(
                    admin["password_hash"], "changed-development-password"
                )
            )
        finally:
            gym_app.app.config["ADMIN_USERNAME"] = original_username
            gym_app.app.config["ADMIN_PASSWORD"] = original_password
            gym_app.app.config["ADMIN_CREDENTIALS_CONFIGURED"] = (
                original_credentials_configured
            )
            gym_app.init_db()

    def test_protected_routes_redirect_and_logout_clears_session(self):
        anonymous_client = gym_app.app.test_client()
        for path in ("/", "/dashboard", "/members"):
            response = anonymous_client.get(path, follow_redirects=False)
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location.partition("?")[0], "/login")

        login_page = anonymous_client.get("/login")
        self.assertEqual(login_page.status_code, 200)

        for path in (
            "/members/add", "/members/1/edit", "/members/1",
            "/members/1/payments", "/payments", "/payments/add", "/due-fees",
            "/reminders", "/payments/1/receipt", "/database/backup",
        ):
            response = anonymous_client.get(path, follow_redirects=False)
            self.assertEqual(response.status_code, 302, path)
            self.assertEqual(response.location.partition("?")[0], "/login")

        protected_post = anonymous_client.post(
            "/members/add", data={}, follow_redirects=False
        )
        self.assertEqual(protected_post.status_code, 302)
        self.assertEqual(protected_post.location.partition("?")[0], "/login")

        login_response = anonymous_client.post(
            "/login", data={"username": "admin", "password": "admin123"}
        )
        self.assertEqual(login_response.status_code, 302)
        self.assertEqual(login_response.location, "/dashboard")
        self.assertEqual(anonymous_client.get("/dashboard").status_code, 200)
        self.assertEqual(anonymous_client.get("/").status_code, 200)
        self.assertEqual(anonymous_client.get("/members").status_code, 200)

        logout_response = self.client.post("/logout")
        self.assertEqual(logout_response.status_code, 302)
        self.assertEqual(logout_response.location, "/login")
        for path in ("/", "/dashboard", "/members"):
            response = self.client.get(path, follow_redirects=False)
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location.partition("?")[0], "/login")
        self.assertEqual(self.client.post("/payments/add", data={}).status_code, 302)

    def test_demo_mode_allows_anonymous_access_and_keeps_data_visible(self):
        member_id = self.create_member(
            "Demo Mode Member", "9876543200", date.today() + timedelta(days=20)
        )
        self.create_payment(member_id, transaction_id="DEMO-TEST-001")
        anonymous_client = gym_app.app.test_client()
        gym_app.app.config["DEMO_MODE"] = True
        try:
            pages = (
                "/", "/dashboard", "/members", "/members/add",
                f"/members/{member_id}", f"/members/{member_id}/edit",
                f"/members/{member_id}/payments", "/payments", "/payments/add",
                "/due-fees", "/reminders", f"/payments/1/receipt",
                "/database/backup",
            )
            for path in pages:
                response = anonymous_client.get(path, follow_redirects=False)
                self.assertEqual(response.status_code, 200, path)

            dashboard = anonymous_client.get("/")
            self.assertEqual(dashboard.status_code, 200)
            self.assertIn(b"Good work starts here.", dashboard.data)
            self.assertIn(b"TOTAL MEMBERS", dashboard.data)
            self.assertIn(b"Record payment", dashboard.data)
            for navigation_item in (
                b"Members", b"Add member", b"Payments",
                b"Record payment", b"Due fees",
            ):
                self.assertIn(navigation_item, dashboard.data)
            self.assertIn(b"Demo Mode Member", dashboard.data)
            self.assertIn(
                b"Demo Mode Member", anonymous_client.get("/members").data
            )

            payment_page = anonymous_client.get("/payments")
            self.assertIn(b"Demo Mode Member", payment_page.data)
            self.assertIn(b"DEMO-TEST-001", payment_page.data)

            due_fees_page = anonymous_client.get("/due-fees")
            self.assertIn(b"Demo Mode Member", due_fees_page.data)
            self.assertIn(
                gym_app.next_month(date.today()).isoformat().encode(),
                due_fees_page.data,
            )
        finally:
            gym_app.app.config["DEMO_MODE"] = False

    def test_admin_initialization_preserves_members_and_payments(self):
        member_id = self.create_member(
            "Preserved Member", "9876543299", date.today() + timedelta(days=20)
        )
        self.create_payment(member_id)
        with gym_app.get_db_connection() as connection:
            initial_counts = (
                connection.execute("SELECT COUNT(*) FROM members").fetchone()[0],
                connection.execute("SELECT COUNT(*) FROM payments").fetchone()[0],
            )
            initial_admin = connection.execute(
                "SELECT username, password_hash FROM admins LIMIT 1"
            ).fetchone()

        gym_app.init_db()

        with gym_app.get_db_connection() as connection:
            final_counts = (
                connection.execute("SELECT COUNT(*) FROM members").fetchone()[0],
                connection.execute("SELECT COUNT(*) FROM payments").fetchone()[0],
            )
            final_admin = connection.execute(
                "SELECT username, password_hash FROM admins LIMIT 1"
            ).fetchone()
        self.assertEqual(final_counts, initial_counts)
        self.assertEqual(tuple(final_admin), tuple(initial_admin))

    def test_member_search_matches_name_phone_email_and_plan(self):
        self.create_member(
            "Searchable Member", "9876543270", date.today() + timedelta(days=20)
        )
        with gym_app.get_db_connection() as connection:
            connection.execute(
                "UPDATE members SET email = ? WHERE phone = ?",
                ("searchable@example.com", "9876543270"),
            )

        for query in ("Searchable", "9876543270", "searchable@example.com", "Monthly"):
            with self.subTest(query=query):
                response = self.client.get("/members", query_string={"q": query})
                self.assertEqual(response.status_code, 200)
                self.assertIn(b"Searchable Member", response.data)

        no_match = self.client.get("/members", query_string={"q": "not-found"})
        self.assertEqual(no_match.status_code, 200)
        self.assertNotIn(b"Searchable Member", no_match.data)
        self.assertIn(b'name="q"', no_match.data)

    def test_database_backup_is_authenticated_and_integrity_checked(self):
        anonymous_client = gym_app.app.test_client()
        self.assertEqual(
            anonymous_client.get("/database/backup").status_code, 302
        )

        response = self.client.get("/database/backup")
        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment", response.headers["Content-Disposition"])
        self.assertTrue(response.data.startswith(b"SQLite format 3\x00"))

        backup_path = Path(self.temp_dir.name) / "downloaded-backup.db"
        backup_path.write_bytes(response.data)
        connection = sqlite3.connect(backup_path)
        try:
            self.assertEqual(
                connection.execute("PRAGMA integrity_check").fetchone()[0], "ok"
            )
        finally:
            connection.close()

    def test_initialization_migrates_existing_payment_periods(self):
        legacy_database = self.database_path.parent / "legacy_gym.db"
        payment_date = date.today() - timedelta(days=12)
        connection = sqlite3.connect(legacy_database)
        try:
            connection.executescript(
                """
                CREATE TABLE members (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    phone TEXT NOT NULL,
                    email TEXT,
                    age INTEGER NOT NULL,
                    gender TEXT NOT NULL,
                    joining_date TEXT NOT NULL,
                    membership_plan TEXT NOT NULL,
                    monthly_fee REAL NOT NULL,
                    start_date TEXT NOT NULL,
                    due_date TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'Active'
                        CHECK (status IN ('Active', 'Inactive')),
                    notes TEXT
                );
                CREATE TABLE payments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    member_id INTEGER NOT NULL,
                    payment_date TEXT NOT NULL,
                    amount REAL NOT NULL CHECK (amount > 0),
                    payment_method TEXT NOT NULL CHECK (
                        payment_method IN ('Cash', 'UPI', 'Card', 'Bank Transfer')
                    ),
                    transaction_id TEXT,
                    notes TEXT,
                    FOREIGN KEY (member_id) REFERENCES members (id) ON DELETE RESTRICT
                );
                """
            )
            connection.execute(
                """
                INSERT INTO members (
                    name, phone, email, age, gender, joining_date,
                    membership_plan, monthly_fee, start_date, due_date,
                    status, notes
                ) VALUES (?, ?, '', 24, 'Other', ?, 'Monthly', 1500, ?, ?, 'Active', '')
                """,
                (
                    "Legacy Member", "9876543298", payment_date.isoformat(),
                    payment_date.isoformat(), date.today().isoformat(),
                ),
            )
            connection.execute(
                """
                INSERT INTO payments (
                    member_id, payment_date, amount, payment_method,
                    transaction_id, notes
                ) VALUES (1, ?, 1500, 'Cash', 'LEGACY-001', '')
                """,
                (payment_date.isoformat(),),
            )
            connection.commit()
        finally:
            connection.close()

        original_database = gym_app.DATABASE
        try:
            gym_app.DATABASE = legacy_database
            gym_app.init_db()
            with gym_app.get_db_connection() as connection:
                member = connection.execute(
                    "SELECT start_date, due_date FROM members WHERE id = 1"
                ).fetchone()
                payment = connection.execute(
                    "SELECT duration_months, start_date, expiry_date, "
                    "transaction_id, membership_plan, member_name, member_phone "
                    "FROM payments WHERE id = 1"
                ).fetchone()
            expected_expiry = gym_app.next_month(payment_date).isoformat()
            self.assertEqual(member["start_date"], payment_date.isoformat())
            self.assertEqual(member["due_date"], expected_expiry)
            self.assertEqual(payment["duration_months"], 1)
            self.assertEqual(payment["start_date"], payment_date.isoformat())
            self.assertEqual(payment["expiry_date"], expected_expiry)
            self.assertEqual(payment["transaction_id"], "LEGACY-001")
            self.assertEqual(payment["membership_plan"], "Monthly")
            self.assertEqual(payment["member_name"], "Legacy Member")
            self.assertEqual(payment["member_phone"], "9876543298")
        finally:
            gym_app.DATABASE = original_database

    def create_member(self, name, phone, due_date):
        today = date.today()
        form = {
            "name": name,
            "phone": phone,
            "email": "",
            "age": "24",
            "gender": "Other",
            "joining_date": today.isoformat(),
            "membership_plan": "Monthly",
            "monthly_fee": "1500",
            "start_date": (today - timedelta(days=30)).isoformat(),
            "due_date": due_date.isoformat(),
            "status": "Active",
            "notes": "",
        }
        response = self.client.post("/members/add", data=form)
        self.assertEqual(response.status_code, 302)
        with gym_app.get_db_connection() as connection:
            return connection.execute(
                "SELECT id FROM members WHERE phone = ?", (phone,)
            ).fetchone()["id"]

    def create_payment(self, member_id, **overrides):
        form_page = self.client.get("/payments/add")
        self.assertEqual(form_page.status_code, 200)
        token_match = re.search(
            rb'name="submission_token" value="([^"]+)"', form_page.data
        )
        self.assertIsNotNone(token_match)
        values = {
            "submission_token": token_match.group(1).decode(),
            "member_id": str(member_id),
            "payment_date": date.today().isoformat(),
            "amount": "1500.00",
            "payment_method": "UPI",
            "transaction_id": "UPI-TEST-001",
            "notes": "Monthly membership fee",
        }
        values.update(overrides)
        return self.client.post("/payments/add", data=values)

    def test_replayed_payment_submission_does_not_create_duplicate(self):
        member_id = self.create_member(
            "One-time Payment Member",
            "9876543271",
            date.today() + timedelta(days=20),
        )
        form_page = self.client.get("/payments/add")
        token_match = re.search(
            rb'name="submission_token" value="([^"]+)"', form_page.data
        )
        self.assertIsNotNone(token_match)
        values = {
            "submission_token": token_match.group(1).decode(),
            "member_id": str(member_id),
            "payment_date": date.today().isoformat(),
            "amount": "1500",
            "payment_method": "Cash",
            "duration_months": "1",
            "start_date": date.today().isoformat(),
            "expiry_date": gym_app.next_month(date.today()).isoformat(),
        }

        first_response = self.client.post("/payments/add", data=values)
        duplicate_response = self.client.post("/payments/add", data=values)
        self.assertEqual(first_response.status_code, 302)
        self.assertEqual(duplicate_response.status_code, 302)
        self.assertEqual(first_response.location, duplicate_response.location)
        with gym_app.get_db_connection() as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM payments").fetchone()[0],
                1,
            )

    def test_payment_routes_history_dashboard_and_deactivation(self):
        member_id = self.create_member(
            "Mira Test", "9876543210", date.today() + timedelta(days=20)
        )

        self.assertEqual(self.client.get("/payments").status_code, 200)
        self.assertEqual(self.client.get("/payments/add").status_code, 200)
        response = self.create_payment(member_id)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/payments?receipt_id=", response.location)

        ledger = self.client.get("/payments")
        self.assertEqual(ledger.status_code, 200)
        self.assertIn(b"UPI-TEST-001", ledger.data)
        self.assertIn(b"Monthly membership fee", ledger.data)
        self.assertIn(b"Mira Test", ledger.data)
        payment_id = int(response.location.partition("receipt_id=")[2])
        receipt = self.client.get(f"/payments/{payment_id}/receipt")
        self.assertEqual(receipt.status_code, 200)
        for receipt_value in (
            "Form &amp; Function", "Mira Test", "9876543210",
            "₹1500.00", "UPI", "Monthly",
        ):
            self.assertIn(receipt_value.encode(), receipt.data)
        self.assertIn(b"Print Receipt", receipt.data)
        self.assertIn(b"Membership start date", receipt.data)
        self.assertIn(b"Membership expiry date", receipt.data)
        self.assertIn(b"View Receipt", ledger.data)

        success_page = self.client.get(response.location)
        self.assertIn(b"View Receipt", success_page.data)
        self.assertEqual(self.client.get("/payments/9999/receipt").status_code, 404)

        profile = self.client.get(f"/members/{member_id}")
        history = self.client.get(f"/members/{member_id}/payments")
        dashboard = self.client.get("/")
        self.assertEqual(profile.status_code, 200)
        self.assertIn(b"TOTAL PAID", profile.data)
        self.assertIn(b"UPI-TEST-001", profile.data)
        self.assertEqual(history.status_code, 200)
        self.assertIn(b"Monthly membership fee", history.data)
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn(b"PAYMENTS RECEIVED", dashboard.data)

        with gym_app.get_db_connection() as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM members").fetchone()[0], 1
            )
            member = connection.execute(
                "SELECT * FROM members WHERE id = ?", (member_id,)
            ).fetchone()

        member_form = {key: member[key] for key in member.keys() if key != "id"}
        updated_joining_date = (date.today() - timedelta(days=14)).isoformat()
        updated_start_date = date.today().isoformat()
        updated_expiry_date = gym_app.next_month(date.today()).isoformat()
        member_form.update(
            name="Mira Updated",
            phone="9876543266",
            joining_date=updated_joining_date,
            membership_plan="Annual",
            monthly_fee="18000",
            start_date=updated_start_date,
            due_date=updated_expiry_date,
        )
        member_form["status"] = "Inactive"
        self.assertEqual(
            self.client.post(f"/members/{member_id}/edit", data=member_form).status_code,
            302,
        )
        with gym_app.get_db_connection() as connection:
            updated_member = connection.execute(
                "SELECT * FROM members WHERE id = ?", (member_id,)
            ).fetchone()
        self.assertEqual(updated_member["name"], "Mira Updated")
        self.assertEqual(updated_member["phone"], "9876543266")
        self.assertEqual(updated_member["joining_date"], updated_joining_date)
        self.assertEqual(updated_member["membership_plan"], "Annual")
        self.assertEqual(updated_member["monthly_fee"], 18000)
        self.assertEqual(updated_member["start_date"], updated_start_date)
        self.assertEqual(updated_member["due_date"], updated_expiry_date)
        self.assertEqual(updated_member["status"], "Inactive")
        receipt_after_member_edit = self.client.get(
            f"/payments/{payment_id}/receipt"
        )
        self.assertIn(b"Mira Test", receipt_after_member_edit.data)
        self.assertIn(b"9876543210", receipt_after_member_edit.data)
        self.assertIn(b"Monthly", receipt_after_member_edit.data)
        self.assertNotIn(b"Mira Updated", receipt_after_member_edit.data)
        self.assertEqual(
            self.client.get(f"/members/{member_id}/payments").status_code, 200
        )
        with gym_app.get_db_connection() as connection:
            payment_count = connection.execute(
                "SELECT COUNT(*) FROM payments WHERE member_id = ?", (member_id,)
            ).fetchone()[0]
        self.assertEqual(payment_count, 1)

    def test_payment_saves_membership_period_and_updates_member_and_dashboard(self):
        today = date.today()
        member_id = self.create_member(
            "Membership Update Member", "9876543220", today + timedelta(days=20)
        )
        start_date = today.isoformat()
        expiry_date = gym_app.next_month(gym_app.next_month(today)).isoformat()

        response = self.create_payment(
            member_id,
            amount="3000",
            duration_months="2",
            start_date=start_date,
            expiry_date=expiry_date,
        )
        self.assertEqual(response.status_code, 302)

        with gym_app.get_db_connection() as connection:
            member = connection.execute(
                "SELECT * FROM members WHERE id = ?", (member_id,)
            ).fetchone()
            payment = connection.execute(
                "SELECT * FROM payments WHERE member_id = ?", (member_id,)
            ).fetchone()
            fee_info = gym_app.get_fee_info(connection, member)

        self.assertEqual(member["start_date"], start_date)
        self.assertEqual(member["due_date"], expiry_date)
        self.assertEqual(member["monthly_fee"], 1500)
        self.assertEqual(payment["duration_months"], 2)
        self.assertEqual(payment["start_date"], start_date)
        self.assertEqual(payment["expiry_date"], expiry_date)
        self.assertEqual(fee_info["next_due_date"], expiry_date)

        dashboard = self.client.get("/")
        self.assertIn("₹3000".encode(), dashboard.data)
        self.assertIn(expiry_date.encode(), self.client.get(f"/members/{member_id}").data)
        self.assertIn(b"2 months", self.client.get("/payments").data)

    def test_payment_validation_and_unknown_member(self):
        member_id = self.create_member(
            "Valid Member", "9876543211", date.today() + timedelta(days=20)
        )
        invalid_amount = self.create_payment(member_id, amount="0")
        invalid_method = self.create_payment(member_id, payment_method="Cheque")
        invalid_period = self.create_payment(
            member_id, duration_months="0",
            start_date=date.today().isoformat(),
            expiry_date=(date.today() + timedelta(days=30)).isoformat(),
        )
        unknown_member = self.create_payment(99999)
        self.assertEqual(invalid_amount.status_code, 200)
        self.assertIn(b"Payment amount must be greater than 0", invalid_amount.data)
        self.assertEqual(invalid_method.status_code, 200)
        self.assertIn(b"Select a valid payment method", invalid_method.data)
        self.assertEqual(invalid_period.status_code, 200)
        self.assertIn(b"Membership duration must be between 1 and 60 months", invalid_period.data)
        self.assertEqual(unknown_member.status_code, 200)
        self.assertIn(b"selected member does not exist", unknown_member.data)

        with gym_app.get_db_connection() as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM members").fetchone()[0], 1
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM payments").fetchone()[0], 0
            )

    def test_monthly_due_dates_dashboard_counts_and_fee_list(self):
        today = date.today()
        due_soon_id = self.create_member(
            "Due Soon Member", "9876543212", today + timedelta(days=3)
        )
        self.create_member(
            "Overdue Member", "9876543213", today - timedelta(days=1)
        )

        due_page = self.client.get("/due-fees")
        dashboard = self.client.get("/")
        self.assertEqual(due_page.status_code, 200)
        self.assertIn(b"Due Soon Member", due_page.data)
        self.assertIn(b"Due Soon", due_page.data)
        self.assertIn(b"Overdue Member", due_page.data)
        self.assertIn(b"Overdue", due_page.data)
        self.assertIn(b"FEES DUE SOON", dashboard.data)
        self.assertIn(b"FEES OVERDUE", dashboard.data)

        self.create_payment(due_soon_id)
        profile = self.client.get(f"/members/{due_soon_id}")
        with gym_app.get_db_connection() as connection:
            member = connection.execute(
                "SELECT * FROM members WHERE id = ?", (due_soon_id,)
            ).fetchone()
            fee_info = gym_app.get_fee_info(connection, member)
        expected_due = gym_app.next_month(today).isoformat()
        self.assertEqual(fee_info["next_due_date"], expected_due)
        self.assertIn(expected_due.encode(), profile.data)
        self.assertEqual(fee_info["fee_status"], "Paid")

    def test_payment_expiry_matches_duration_and_clamps_month_end(self):
        start_date = date(2026, 1, 31)
        self.assertEqual(gym_app.add_months(start_date, 1), date(2026, 2, 28))
        self.assertEqual(gym_app.add_months(start_date, 2), date(2026, 3, 31))

        member_id = self.create_member(
            "Expiry Validation Member",
            "9876543272",
            date.today() + timedelta(days=20),
        )
        invalid_period = self.create_payment(
            member_id,
            duration_months="2",
            start_date=date.today().isoformat(),
            expiry_date=gym_app.next_month(date.today()).isoformat(),
        )
        self.assertEqual(invalid_period.status_code, 200)
        self.assertIn(
            b"Membership expiry date must match its start date and duration",
            invalid_period.data,
        )

    def test_reminder_status_calculations_and_message_templates(self):
        expected_statuses = {
            -2: "Expired-membership message",
            -1: "Expired-membership message",
            0: "Expiry-day message",
            1: "1-day reminder",
            2: "3-day reminder",
            3: "3-day reminder",
            4: "7-day reminder",
            7: "7-day reminder",
            8: None,
        }
        for days_remaining, expected in expected_statuses.items():
            with self.subTest(days_remaining=days_remaining):
                self.assertEqual(
                    gym_app.get_reminder_status(days_remaining), expected
                )

        today = date.today()
        for days_remaining, expected_text in (
            (7, "7-day reminder"),
            (3, "There are 3 days left"),
            (1, "expires tomorrow"),
            (0, "expires today"),
            (-1, "expired on"),
        ):
            member = {
                "name": "Reminder Member",
                "due_date": (today + timedelta(days=days_remaining)).isoformat(),
            }
            message = gym_app.build_membership_reminder_message(
                member, days_remaining
            )
            with self.subTest(message_for=days_remaining):
                self.assertIn("Reminder Member", message)
                self.assertIn(expected_text, message)

        with self.assertRaises(ValueError):
            gym_app.build_membership_reminder_message(
                {"name": "Future Member", "due_date": (today + timedelta(days=8)).isoformat()},
                8,
            )

    def test_reminder_center_lists_unique_active_members_with_copy_messages(self):
        today = date.today()
        member_ids = {
            7: self.create_member(
                "Seven Day Reminder", "9876543230", today + timedelta(days=7)
            ),
            3: self.create_member(
                "Three Day Reminder", "9876543231", today + timedelta(days=3)
            ),
            1: self.create_member(
                "Tomorrow Reminder", "9876543232", today + timedelta(days=1)
            ),
            0: self.create_member(
                "Today Reminder", "9876543233", today
            ),
            -1: self.create_member(
                "Expired Reminder", "9876543234", today - timedelta(days=1)
            ),
            8: self.create_member(
                "Not Yet Reminder", "9876543235", today + timedelta(days=8)
            ),
        }
        inactive_id = self.create_member(
            "Inactive Reminder", "9876543236", today + timedelta(days=2)
        )
        with gym_app.get_db_connection() as connection:
            connection.execute(
                "UPDATE members SET status = 'Inactive' WHERE id = ?",
                (inactive_id,),
            )
            connection.executemany(
                """
                INSERT INTO payments (
                    member_id, payment_date, amount, payment_method,
                    duration_months, start_date, expiry_date
                ) VALUES (?, ?, 1500, 'Cash', 1, ?, ?)
                """,
                [
                    (
                        member_ids[3],
                        today.isoformat(),
                        today.isoformat(),
                        (today + timedelta(days=3)).isoformat(),
                    ),
                    (
                        member_ids[3],
                        (today - timedelta(days=30)).isoformat(),
                        (today - timedelta(days=30)).isoformat(),
                        today.isoformat(),
                    ),
                ],
            )

        response = self.client.get("/reminders")
        self.assertEqual(response.status_code, 200)
        for name in (
            "Seven Day Reminder",
            "Three Day Reminder",
            "Tomorrow Reminder",
            "Today Reminder",
            "Expired Reminder",
        ):
            self.assertIn(name.encode(), response.data)
        for name in ("Not Yet Reminder", "Inactive Reminder"):
            self.assertNotIn(name.encode(), response.data)
        for status in (
            "7-day reminder",
            "3-day reminder",
            "1-day reminder",
            "Expiry-day message",
            "Expired-membership message",
        ):
            self.assertIn(status.encode(), response.data)
        self.assertIn(b"9876543233", response.data)
        self.assertIn(b"Copy Message", response.data)
        self.assertEqual(
            response.data.count(
                f'href="/members/{member_ids[3]}"'.encode()
            ),
            1,
        )

    def test_fee_status_filters_dashboard_reminders_and_payment_recovery(self):
        today = date.today()
        due_soon_id = self.create_member(
            "Filter Due Soon", "9876543214", today + timedelta(days=7)
        )
        due_today_id = self.create_member(
            "Filter Due Today", "9876543215", today
        )
        overdue_id = self.create_member(
            "Filter Overdue", "9876543216", today - timedelta(days=4)
        )
        paid_id = self.create_member(
            "Filter Paid", "9876543217", today + timedelta(days=8)
        )

        with gym_app.get_db_connection() as connection:
            for member_id, expected_status in (
                (due_soon_id, "Due Soon"),
                (due_today_id, "Due Today"),
                (overdue_id, "Overdue"),
                (paid_id, "Paid"),
            ):
                member = connection.execute(
                    "SELECT * FROM members WHERE id = ?", (member_id,)
                ).fetchone()
                self.assertEqual(
                    gym_app.get_fee_info(connection, member)["fee_status"],
                    expected_status,
                )

        all_fees = self.client.get("/due-fees?status=All")
        self.assertEqual(all_fees.status_code, 200)
        for name in (
            "Filter Due Soon", "Filter Due Today", "Filter Overdue", "Filter Paid"
        ):
            self.assertIn(name.encode(), all_fees.data)

        for status, included, excluded in (
            ("Due Soon", "Filter Due Soon", "Filter Due Today"),
            ("Due Today", "Filter Due Today", "Filter Due Soon"),
            ("Overdue", "Filter Overdue", "Filter Due Today"),
        ):
            response = self.client.get(f"/due-fees?status={status.replace(' ', '%20')}")
            self.assertEqual(response.status_code, 200)
            self.assertIn(included.encode(), response.data)
            self.assertNotIn(excluded.encode(), response.data)

        dashboard = self.client.get("/")
        self.assertIn(b"FEES DUE SOON", dashboard.data)
        self.assertIn(b"FEES DUE TODAY", dashboard.data)
        self.assertIn(b"FEES OVERDUE", dashboard.data)
        self.assertIn(b"TOTAL OUTSTANDING", dashboard.data)
        self.assertIn("₹3000".encode(), dashboard.data)
        self.assertRegex(
            dashboard.data.decode(),
            re.compile(r"FEES DUE TODAY</span>.*?<div class=\"stat-number\">1</div>", re.S),
        )

        reminder = self.client.post(
            f"/members/{due_today_id}/reminder",
            data={"status_filter": "Due Today"},
            follow_redirects=True,
        )
        self.assertIn(b"Fee reminder prepared for Filter Due Today.", reminder.data)
        self.assertIn(b"Reminder message", reminder.data)
        self.assertIn(b"Send Reminder", reminder.data)
        self.assertIn(b"Your gym membership fee of", reminder.data)
        with gym_app.get_db_connection() as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM payments").fetchone()[0], 0
            )

        overdue_payment = self.create_payment(overdue_id)
        self.assertEqual(overdue_payment.status_code, 302)
        with gym_app.get_db_connection() as connection:
            member = connection.execute(
                "SELECT * FROM members WHERE id = ?", (overdue_id,)
            ).fetchone()
            fee_info = gym_app.get_fee_info(connection, member)
            payment_count = connection.execute(
                "SELECT COUNT(*) FROM payments WHERE member_id = ?", (overdue_id,)
            ).fetchone()[0]
        self.assertEqual(fee_info["fee_status"], "Paid")
        self.assertEqual(fee_info["last_payment_date"], today.isoformat())
        self.assertEqual(payment_count, 1)
        profile = self.client.get(f"/members/{overdue_id}")
        self.assertIn(b"LAST PAYMENT", profile.data)
        self.assertIn(today.isoformat().encode(), profile.data)
        self.assertIn(b"Payment history", profile.data)

    def test_next_month_clamps_to_month_end(self):
        self.assertEqual(gym_app.next_month(date(2024, 1, 31)), date(2024, 2, 29))
        self.assertEqual(gym_app.next_month(date(2025, 1, 31)), date(2025, 2, 28))
        self.assertEqual(gym_app.next_month(date(2026, 12, 31)), date(2027, 1, 31))


if __name__ == "__main__":
    unittest.main()