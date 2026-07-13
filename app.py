# ============================================================
# ADMIN BACKEND - AUTH + DASHBOARD + FORGOT PASSWORD (OTP)
# ============================================================

# -------------------- BASIC IMPORTS -------------------------
from dotenv import load_dotenv
load_dotenv() 
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
import pymysql
import jwt
import os
import uuid
import random
import requests
import os

from datetime import datetime, timedelta
import pytz
from db import get_db


# ============================================================
# LOAD ENV
# ============================================================
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
SMTP_PASS = os.getenv("BREVO_SMTP_PASS")



if not SECRET_KEY:
    raise Exception("SECRET_KEY missing in .env")
if not SMTP_PASS:
    raise Exception("BREVO_SMTP_PASS missing in .env")

# ============================================================
# EMAIL CONFIG (BREVO)
# ============================================================
SMTP_SERVER = "smtp-relay.brevo.com"
SMTP_PORT = 587
SMTP_USER = "9da39b001@smtp-brevo.com"
FROM_EMAIL = "techpallotine@gmail.com"

BREVO_API_KEY = os.getenv("ADMIN_KEY") 


# ============================================================
# FLASK SETUP
# ============================================================
app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
CORS(app)

# ============================================================
# TIMEZONE + OTP CONFIG
# ============================================================
IST = pytz.timezone("Asia/Kolkata")

ADMIN_OTP_VALID_MINUTES = 5
admin_otp_store = {}
# 🔐 In-memory OTP store (temporary)
admin_login_otp_store = {}


from datetime import datetime
import pytz

IST = pytz.timezone("Asia/Kolkata")

def now_ist():
    return datetime.now(IST)

def dt_to_str(dt):
    if dt is None:
        return None
    return dt.astimezone(IST).strftime("%Y-%m-%d %H:%M:%S")


# ============================================================
# DATABASE CONNECTION
# ============================================================



# ============================================================
# JWT DECORATOR (ADMIN)
# ============================================================
def admin_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        # ✅ VERY IMPORTANT: allow OPTIONS preflight
        if request.method == "OPTIONS":
            return jsonify({"success": True}), 200

        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Token missing"}), 401

        token = auth.replace("Bearer ", "")

        db = None
        cur = None
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

            # ✅ admin validation (correct)
            if payload.get("type") != "admin":
                return jsonify({"error": "Invalid admin token"}), 403

            admin_uid = payload.get("admin_uid")

            db = get_db()
            cur = db.cursor()

            cur.execute(
                "SELECT * FROM admins WHERE admin_uid=%s AND is_active=1",
                (admin_uid,)
            )
            admin = cur.fetchone()

            if not admin:
                return jsonify({"error": "Admin not found"}), 401

        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        finally:
            if cur:
                cur.close()
            if db:
                db.close()   # 🔥 return connection to pool

        return f(admin, *args, **kwargs)

    return decorated


# ============================================================
# ADMIN SIGNUP (TEMP)
# ============================================================
@app.route("/api/admin/signup", methods=["POST"])
def admin_signup():
    data = request.get_json() or {}

    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    if not name or not email or not password:
        return jsonify({"error": "All fields required"}), 400

    db = None
    cur = None
    try:
        db = get_db()
        cur = db.cursor()

        cur.execute("SELECT id FROM admins WHERE email=%s", (email,))
        if cur.fetchone():
            return jsonify({"error": "Admin already exists"}), 409

        cur.execute(
            """
            INSERT INTO admins (admin_uid, name, email, password_hash, role, is_active)
            VALUES (%s, %s, %s, %s, %s, 1)
            """,
            (
                str(uuid.uuid4()),
                name,
                email,
                generate_password_hash(password),
                "admin"
            )
        )

        return jsonify({"success": True, "message": "Admin created"}), 201

    finally:
        if cur:
            cur.close()
        if db:
            db.close()   # 🔥 returns connection to pool


# ============================================================
@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json(silent=True) or {}

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    db = get_db()
    cur = db.cursor(pymysql.cursors.DictCursor)

    cur.execute(
        "SELECT * FROM admins WHERE email=%s AND is_active=1",
        (email,)
    )
    admin = cur.fetchone()

    cur.close()
    db.close()

    if not admin:
        return jsonify({"error": "Admin not found"}), 401

    if not check_password_hash(admin["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    # 🔐 Generate OTP
    otp = generate_otp()
    expires_at = datetime.utcnow() + timedelta(minutes=5)

    admin_login_otp_store[email] = {
        "otp": otp,
        "expires_at": expires_at
    }

    # 📧 Send OTP
    send_otp_email(email, otp)

    return jsonify({
        "success": True,
        "otp_required": True,
        "message": "OTP sent to registered email"
    }), 200


@app.route("/api/admin/verify-login-otp", methods=["POST"])
def verify_admin_login_otp():
    data = request.get_json(silent=True) or {}

    email = data.get("email")
    otp = data.get("otp")

    if not email or not otp:
        return jsonify({"error": "Email and OTP required"}), 400

    record = admin_login_otp_store.get(email)

    if not record:
        return jsonify({"error": "OTP not found or expired"}), 400

    if datetime.utcnow() > record["expires_at"]:
        del admin_login_otp_store[email]
        return jsonify({"error": "OTP expired"}), 400

    if record["otp"] != otp:
        return jsonify({"error": "Invalid OTP"}), 400

    # 🔑 Fetch admin
    db = get_db()
    cur = db.cursor(pymysql.cursors.DictCursor)

    cur.execute(
        "SELECT admin_uid, name, email FROM admins WHERE email=%s",
        (email,)
    )
    admin = cur.fetchone()

    cur.close()
    db.close()

    # 🧹 Remove OTP after success
    del admin_login_otp_store[email]

    # 🎫 Issue JWT
    token = jwt.encode(
        {
            "admin_uid": admin["admin_uid"],
            "type": "admin",
            "exp": datetime.utcnow() + timedelta(hours=8)
        },
        SECRET_KEY,
        algorithm="HS256"
    )

    return jsonify({
        "success": True,
        "token": token,
        "admin": {
            "name": admin["name"],
            "email": admin["email"]
        }
    }), 200






# ============================================================
# OTP HELPERS
# ============================================================
def generate_otp():
    return str(random.randint(100000, 999999))

def load_html_template(filename, **kwargs):
    template_path = os.path.join(
        os.path.dirname(__file__),
        "templates",
        filename
    )

    if not os.path.exists(template_path):
        raise FileNotFoundError(f"{filename} not found")

    with open(template_path, "r", encoding="utf-8") as f:
        html = f.read()

    # Replace placeholders {{key}}
    for key, value in kwargs.items():
        html = html.replace(f"{{{{{key}}}}}", str(value))

    return html



def send_otp_email(email, otp):
    """
    Send OTP email using Brevo (Sendinblue) HTTP API
    Safe for Render / local / slow networks
    """

    BREVO_API_KEY = os.getenv("ADMIN_KEY")

    if not BREVO_API_KEY:
        print("ADMIN_KEY not set")
        return False

    html = load_html_template(
        "admin_otp_template.html",
        otp=otp,
        year=datetime.now().year
    )

    url = "https://api.brevo.com/v3/smtp/email"

    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json",
    }

    payload = {
        "sender": {
            "name": "Skill Sphere Admin",
            "email": "techpallotine@gmail.com"  # must be verified
        },
        "to": [{"email": email}],
        "subject": "Admin Password Reset OTP",
        "htmlContent": html
    }

    try:
        response = requests.post(
            url,
            json=payload,
            headers=headers,
            timeout=10  # 🔥 CRITICAL FIX
        )

        if response.status_code != 201:
            print(
                "Brevo error:",
                response.status_code,
                response.text
            )
            return False

        return True

    except requests.exceptions.RequestException as e:
        # 🔥 NEVER crash login because of email delay
        print("Brevo timeout/network error:", str(e))
        return False

@app.route("/api/admin/resend_otp", methods=["POST"])
def admin_resend_otp():
    data = request.get_json() or {}
    email = data.get("email")

    if not email:
        return jsonify({"error": "Email required"}), 400

    db = None
    cur = None
    try:
        # 🔒 Check admin exists
        db = get_db()
        cur = db.cursor()

        cur.execute(
            "SELECT admin_uid FROM admins WHERE email=%s AND is_active=1",
            (email,)
        )
        admin = cur.fetchone()

    finally:
        if cur:
            cur.close()
        if db:
            db.close()   # 🔥 return to pool

    if not admin:
        return jsonify({"error": "Admin email not found"}), 404

    # 🔄 Generate NEW OTP
    otp = generate_otp()
    now_ist = datetime.now(IST)
    expires_at = now_ist + timedelta(minutes=ADMIN_OTP_VALID_MINUTES)

    # 🔥 Overwrite previous OTP (safe)
    admin_otp_store[email] = {
        "otp": otp,
        "expires_at": expires_at,
        "verified": False
    }

    send_otp_email(email, otp)

    return jsonify({
        "success": True,
        "message": "OTP resent successfully",
        "expires_in_minutes": ADMIN_OTP_VALID_MINUTES
    }), 200


# ============================================================
# FORGOT PASSWORD
# ============================================================
@app.route("/api/admin/forgot_password", methods=["POST"])
def admin_forgot_password():
    data = request.get_json() or {}
    email = data.get("email")

    if not email:
        return jsonify({"error": "Email required"}), 400

    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT admin_uid FROM admins WHERE email=%s AND is_active=1",
        (email,)
    )
    admin = cur.fetchone()
    db.close()

    if not admin:
        return jsonify({"error": "Admin email not found"}), 404

    otp = generate_otp()
    now_ist = datetime.now(IST)
    expires_at = now_ist + timedelta(minutes=ADMIN_OTP_VALID_MINUTES)

    admin_otp_store[email] = {
        "otp": otp,
        "expires_at": expires_at,
        "verified": False
    }

    send_otp_email(email, otp)

    return jsonify({"success": True, "message": "OTP sent"}), 200

# ============================================================
# VERIFY OTP
# ============================================================
@app.route("/api/admin/verify_otp", methods=["POST"])
def admin_verify_otp():
    data = request.get_json() or {}
    email = data.get("email")
    otp = data.get("otp")

    entry = admin_otp_store.get(email)
    if not entry:
        return jsonify({"error": "OTP not requested"}), 400

    if datetime.now(IST) > entry["expires_at"]:
        del admin_otp_store[email]
        return jsonify({"error": "OTP expired"}), 400

    if otp != entry["otp"]:
        return jsonify({"error": "Invalid OTP"}), 400

    entry["verified"] = True
    return jsonify({"success": True, "message": "OTP verified"}), 200

# ============================================================
# RESET PASSWORD
# ============================================================
@app.route("/api/admin/reset_password", methods=["POST"])
def admin_reset_password():
    data = request.get_json() or {}
    email = data.get("email")
    new_password = data.get("new_password")

    entry = admin_otp_store.get(email)
    if not entry or not entry.get("verified"):
        return jsonify({"error": "OTP not verified"}), 400

    hashed = generate_password_hash(new_password)

    db = None
    cur = None
    try:
        db = get_db()
        cur = db.cursor()

        cur.execute(
            "UPDATE admins SET password_hash=%s WHERE email=%s",
            (hashed, email)
        )

    finally:
        if cur:
            cur.close()
        if db:
            db.close()   # 🔥 return to pool

    del admin_otp_store[email]

    return jsonify({"success": True, "message": "Password reset successful"}), 200


# ============================================================
# FETCH STUDENTS (Y2 / Y3)
# ============================================================
# ============================================================
# ADMIN : YEAR-WISE STUDENT LIST
# ============================================================

@app.route("/api/admin/students", methods=["GET", "OPTIONS"])
@admin_token_required
def get_students_yearwise(admin):

    year = request.args.get("year", type=int)

    if year not in [2, 3]:
        return jsonify({
            "success": False,
            "message": "Invalid year"
        }), 400

    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor(pymysql.cursors.DictCursor)

        cur.execute(
            """
            SELECT uid, name, email
            FROM students
            WHERE year = %s
            ORDER BY uid ASC
            """,
            (year,)
        )

        students = cur.fetchall()

        return jsonify({
            "success": True,
            "students": students
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()   # 🔥 return to pool



@app.route("/api/admin/student/<uid>", methods=["GET", "OPTIONS"])
@admin_token_required
def get_single_student(admin, uid):

    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor(pymysql.cursors.DictCursor)

        cur.execute(
            """
            SELECT uid, name, email, year
            FROM students
            WHERE uid = %s
            """,
            (uid,)
        )

        student = cur.fetchone()

        if not student:
            return jsonify({
                "success": False,
                "message": "Student not found"
            }), 404

        return jsonify({
            "success": True,
            "student": student
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()   # 🔥 return to pool



@app.route("/api/admin/student/<uid>/delete", methods=["DELETE", "OPTIONS"])
@admin_token_required
def delete_student(admin, uid):
    if request.method == "OPTIONS":
        return jsonify({"success": True}), 200

    conn = None
    cur = None
    try:
        conn = get_db()
        conn.begin()
        cur = conn.cursor()

        # 1. Delete daily quiz answers & attempts for Y2
        cur.execute("""
            DELETE FROM daily_quiz_answers_y2 
            WHERE attempt_id IN (SELECT id FROM daily_quiz_attempts_y2 WHERE uid = %s)
        """, (uid,))
        cur.execute("DELETE FROM daily_quiz_attempts_y2 WHERE uid = %s", (uid,))

        # 2. Delete daily quiz answers & attempts for Y3
        cur.execute("""
            DELETE FROM daily_quiz_answers_y3 
            WHERE attempt_id IN (SELECT id FROM daily_quiz_attempts_y3 WHERE uid = %s)
        """, (uid,))
        cur.execute("DELETE FROM daily_quiz_attempts_y3 WHERE uid = %s", (uid,))

        # 3. Delete assignment quiz marks for Y2 & Y3
        cur.execute("DELETE FROM assignment_quiz_marks_y2 WHERE uid = %s", (uid,))
        cur.execute("DELETE FROM assignment_quiz_marks_y3 WHERE uid = %s", (uid,))

        # 4. Delete from branchquiz
        cur.execute("DELETE FROM branchquiz WHERE uid_number = %s", (uid,))

        # 5. Delete from quiz_results
        cur.execute("DELETE FROM quiz_results WHERE uid_number = %s", (uid,))

        # 6. Delete the student record
        cur.execute("DELETE FROM students WHERE uid = %s", (uid,))

        conn.commit()
        return jsonify({
            "success": True,
            "message": "Student and all associated records deleted successfully"
        }), 200

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()



@app.route("/api/admin/daily-quiz/topic", methods=["POST", "OPTIONS"])
@admin_token_required
def insert_daily_quiz_topic(admin):

    if request.method == "OPTIONS":
        return jsonify({"success": True}), 200

    data = request.get_json() or {}

    year = data.get("year")
    quiz_date = data.get("quiz_date")
    quiz_type = data.get("quiz_type")
    topic = data.get("topic")
    difficulty = data.get("difficulty")

    # 🔒 VALIDATIONS
    if year not in [2, 3]:
        return jsonify({"error": "Invalid year"}), 400

    if quiz_type not in ["placement", "technical"]:
        return jsonify({"error": "Invalid quiz type"}), 400

    if difficulty not in ["easy", "medium", "hard", "very hard"]:
        return jsonify({"error": "Invalid difficulty"}), 400

    if not quiz_date or not topic:
        return jsonify({"error": "Date and topic are required"}), 400

    table = "daily_quiz_topics_y2" if year == 2 else "daily_quiz_topics_y3"

    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor()

        # ✅ total_questions FORCED = 10
        cur.execute(
            f"""
            INSERT INTO {table}
            (quiz_date, quiz_type, topic, difficulty, total_questions)
            VALUES (%s, %s, %s, %s, 10)
            """,
            (quiz_date, quiz_type, topic, difficulty)
        )

        return jsonify({
            "success": True,
            "message": "Daily quiz topic added successfully"
        }), 201

    except pymysql.err.IntegrityError:
        return jsonify({
            "error": "Quiz already exists for this date"
        }), 409

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()   # 🔥 return to pool


@app.route("/api/admin/daily-quiz/topic/delete", methods=["POST", "OPTIONS"])
@admin_token_required
def delete_daily_quiz_topic(admin):

    if request.method == "OPTIONS":
        return jsonify({"success": True}), 200

    data = request.get_json(silent=True) or {}

    year = data.get("year")
    quiz_date = data.get("quiz_date")

    if year not in [2, 3]:
        return jsonify({"error": "Invalid year"}), 400

    if not quiz_date:
        return jsonify({"error": "Quiz date required"}), 400

    table = "daily_quiz_topics_y2" if year == 2 else "daily_quiz_topics_y3"

    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor()

        cur.execute(
            f"SELECT id FROM {table} WHERE quiz_date=%s",
            (quiz_date,)
        )
        if not cur.fetchone():
            return jsonify({"error": "No quiz found for this date"}), 404

        cur.execute(
            f"DELETE FROM {table} WHERE quiz_date=%s",
            (quiz_date,)
        )

        return jsonify({
            "success": True,
            "message": "Quiz topic removed successfully"
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()   # 🔥 return to pool



import csv
from io import TextIOWrapper

@app.route("/api/admin/faculty-quiz/upload-csv", methods=["POST"])
@admin_token_required
def upload_faculty_quiz_csv(admin):

    if "file" not in request.files:
        return jsonify({"error": "CSV file required"}), 400

    file = request.files["file"]

    if not file.filename.endswith(".csv"):
        return jsonify({"error": "Only .csv files allowed"}), 400

    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor()

        csv_file = TextIOWrapper(file, encoding="utf-8")
        reader = csv.DictReader(csv_file)

        # 🔒 REQUIRED CSV COLUMNS
        required_columns = [
            "quiz_id",
            "question",
            "option_a",
            "option_b",
            "option_c",
            "option_d",
            "correct_option",
        ]

        if reader.fieldnames != required_columns:
            return jsonify({
                "error": "Invalid CSV format",
                "expected_columns": required_columns
            }), 400

        inserted = 0

        for row in reader:
            quiz_id = row["quiz_id"]
            question = row["question"]
            option_a = row["option_a"]
            option_b = row["option_b"]
            option_c = row["option_c"]
            option_d = row["option_d"]
            correct_option = row["correct_option"].upper()

            # 🔍 VALIDATIONS
            if correct_option not in ["A", "B", "C", "D"]:
                return jsonify({
                    "error": f"Invalid correct_option '{correct_option}'"
                }), 400

            if not all([quiz_id, question, option_a, option_b, option_c, option_d]):
                return jsonify({
                    "error": "Empty field detected in CSV"
                }), 400

            # 🔒 Ensure quiz exists
            cur.execute(
                "SELECT quiz_id FROM faculty_quiz_master WHERE quiz_id=%s",
                (quiz_id,)
            )
            if not cur.fetchone():
                return jsonify({
                    "error": f"Quiz ID {quiz_id} does not exist"
                }), 400

            # ✅ INSERT QUESTION
            cur.execute(
                """
                INSERT INTO faculty_quiz_questions_new
                (quiz_id, question, option_a, option_b, option_c, option_d, correct_option)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    quiz_id,
                    question,
                    option_a,
                    option_b,
                    option_c,
                    option_d,
                    correct_option
                )
            )

            inserted += 1

        return jsonify({
            "success": True,
            "message": f"{inserted} questions uploaded successfully"
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()   # 🔥 returns connection to pool


@app.route("/api/admin/faculty-quiz/master", methods=["GET", "OPTIONS"])
@admin_token_required
def get_faculty_quiz_master(admin):

    if request.method == "OPTIONS":
        return jsonify({"success": True}), 200

    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor(pymysql.cursors.DictCursor)

        cur.execute("""
            SELECT
                quiz_id,
                quiz_date,
                quiz_start_time,
                quiz_end_time,
                year,
                created_by
            FROM faculty_quiz_master
            ORDER BY quiz_date DESC, quiz_start_time DESC
        """)

        rows = cur.fetchall()

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()   # 🔥 return to pool

    quizzes = []

    for r in rows:
        quizzes.append({
            "quiz_id": r["quiz_id"],
            "quiz_date": r["quiz_date"].strftime("%Y-%m-%d"),
            "quiz_start_time": r["quiz_start_time"].strftime("%H:%M"),
            "quiz_end_time": r["quiz_end_time"].strftime("%H:%M"),
            "year": r["year"],
            "created_by": r["created_by"],
        })

    return jsonify({
        "success": True,
        "quizzes": quizzes
    }), 200


@app.route("/api/admin/faculty-quiz/create", methods=["POST", "OPTIONS"])
@admin_token_required
def create_faculty_quiz(admin):

    if request.method == "OPTIONS":
        return jsonify({"success": True}), 200

    data = request.json or {}

    quiz_id = data.get("quiz_id")
    quiz_date = data.get("quiz_date")
    quiz_start_time = data.get("quiz_start_time")
    quiz_end_time = data.get("quiz_end_time")
    year = data.get("year")
    created_by = data.get("created_by")

    # -------------------------
    # Validation
    # -------------------------
    if not all([quiz_id, quiz_date, quiz_start_time, quiz_end_time, year, created_by]):
        return jsonify({
            "error": "All fields are required"
        }), 400

    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor()

        # -------------------------
        # Duplicate quiz_id check
        # -------------------------
        cur.execute(
            "SELECT quiz_id FROM faculty_quiz_master WHERE quiz_id = %s",
            (quiz_id,)
        )
        if cur.fetchone():
            return jsonify({
                "error": "Quiz ID already exists"
            }), 409

        # -------------------------
        # Insert (MATCH DB EXACTLY)
        # -------------------------
        cur.execute("""
            INSERT INTO faculty_quiz_master
            (quiz_id, quiz_date, quiz_start_time, quiz_end_time, year, created_by)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            quiz_id,
            quiz_date,
            quiz_start_time,
            quiz_end_time,
            year,
            created_by
        ))

        conn.commit()

        return jsonify({
            "message": "Quiz created successfully"
        }), 201

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()   # 🔥 return to pool



import csv



@app.route("/api/admin/faculty-quiz/search", methods=["GET", "OPTIONS"])
@admin_token_required
def search_faculty_quiz(admin):

    if request.method == "OPTIONS":
        return jsonify({"success": True}), 200

    quiz_id = request.args.get("quiz_id")

    if not quiz_id:
        return jsonify({"quizzes": []}), 200

    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor(pymysql.cursors.DictCursor)

        # 🔥 NOTE: %% is REQUIRED (escape for PyMySQL)
        cur.execute("""
            SELECT
                quiz_id,
                DATE_FORMAT(quiz_date, '%%Y-%%m-%%d') AS quiz_date,
                TIME_FORMAT(quiz_start_time, '%%H:%%i') AS quiz_start_time,
                TIME_FORMAT(quiz_end_time, '%%H:%%i') AS quiz_end_time,
                year,
                created_by
            FROM faculty_quiz_master
            WHERE quiz_id = %s
        """, (quiz_id,))

        row = cur.fetchone()

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()   # 🔥 return to pool

    if not row:
        return jsonify({"quizzes": []}), 200

    # ✅ Already strings → JSON safe
    return jsonify({
        "quizzes": [row]
    }), 200




import io
import csv
from flask import request, jsonify

@app.route("/api/admin/faculty-quiz/questions/check-csv", methods=["POST", "OPTIONS"])
@admin_token_required
def check_questions_csv(admin):

    if request.method == "OPTIONS":
        return jsonify({"success": True}), 200

    print("FILES:", request.files)

    if "file" not in request.files:
        return jsonify({"error": "file not received"}), 400

    file = request.files["file"]

    try:
        content = file.stream.read().decode("utf-8")
        stream = io.StringIO(content)
        reader = csv.DictReader(stream)
    except Exception as e:
        return jsonify({"error": f"Invalid CSV: {str(e)}"}), 400

    REQUIRED_COLUMNS = {
        "question",
        "option_a",
        "option_b",
        "option_c",
        "option_d",
        "correct_option",
    }

    if not reader.fieldnames:
        return jsonify({"error": "CSV header missing"}), 400

    missing = REQUIRED_COLUMNS - set(reader.fieldnames)

    if missing:
        return jsonify({
            "error": "Missing columns",
            "missing": list(missing),
            "received": reader.fieldnames
        }), 400

    return jsonify({
        "message": "CSV structure is valid"
    }), 200




import csv
import io
from flask import request, jsonify

@app.route("/api/admin/faculty-quiz/questions/upload", methods=["POST", "OPTIONS"])
@admin_token_required
def upload_faculty_quiz_questions(admin):
    if request.method == "OPTIONS":
        return jsonify({"success": True}), 200

    conn = None
    cur = None
    try:
        print("FORM:", request.form)
        print("FILES:", request.files)

        quiz_id = request.form.get("quiz_id")
        file = request.files.get("file")

        if not quiz_id:
            return jsonify({"error": "quiz_id missing"}), 400

        if not file:
            return jsonify({"error": "CSV file missing"}), 400

        quiz_id = int(quiz_id)

        # ----------------------------
        # READ CSV
        # ----------------------------
        stream = io.StringIO(file.stream.read().decode("utf-8"))
        reader = csv.DictReader(stream)

        if not reader.fieldnames:
            return jsonify({"error": "CSV has no headers"}), 400

        headers = [h.strip().lower() for h in reader.fieldnames]
        print("CSV HEADERS RECEIVED:", headers)

        required_columns = {
            "question",
            "option_a",
            "option_b",
            "option_c",
            "option_d",
            "correct_option",   # ✅ MATCH DB
        }

        if not required_columns.issubset(headers):
            return jsonify({
                "error": "Invalid CSV format",
                "required_columns": list(required_columns),
                "received_columns": headers
            }), 400

        conn = get_db()
        cur = conn.cursor()

        inserted = 0

        for row in reader:
            row = {k.strip().lower(): (v.strip() if v else "") for k, v in row.items()}

            if not row["question"]:
                continue

            cur.execute(
                """
                INSERT INTO faculty_quiz_questions_new
                (
                    quiz_id,
                    question,
                    option_a,
                    option_b,
                    option_c,
                    option_d,
                    correct_option
                )
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    quiz_id,
                    row["question"],
                    row["option_a"],
                    row["option_b"],
                    row["option_c"],
                    row["option_d"],
                    row["correct_option"],  # ✅ MATCH DB
                ),
            )

            inserted += 1

        conn.commit()

        return jsonify({
            "success": True,
            "message": f"{inserted} questions uploaded successfully",
            "quiz_id": quiz_id
        }), 201

    except Exception as e:
        print("UPLOAD ERROR:", str(e))
        return jsonify({
            "error": "Upload failed",
            "details": str(e)
        }), 500

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()   # 🔥 return connection to pool




@app.route("/api/admin/faculty-quiz/delete", methods=["DELETE", "OPTIONS"])
@admin_token_required
def delete_faculty_quiz(admin):

    if request.method == "OPTIONS":
        return jsonify({"success": True}), 200

    data = request.json or {}
    quiz_id = data.get("quiz_id")

    if not quiz_id:
        return jsonify({
            "success": False,
            "message": "quiz_id required"
        }), 400

    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor()

        # 1️⃣ Delete questions
        cur.execute(
            "DELETE FROM faculty_quiz_questions_new WHERE quiz_id = %s",
            (quiz_id,)
        )

        # 2️⃣ Delete quiz master
        cur.execute(
            "DELETE FROM faculty_quiz_master WHERE quiz_id = %s",
            (quiz_id,)
        )

        conn.commit()

        return jsonify({
            "success": True,
            "message": "Quiz deleted from master and questions table"
        }), 200

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()   # 🔥 return to pool



@app.route("/api/admin/faculty-quiz/delete-search", methods=["GET", "OPTIONS"])
@admin_token_required
def delete_search_faculty_quiz(admin):

    if request.method == "OPTIONS":
        return jsonify({"success": True}), 200

    quiz_id = request.args.get("quiz_id")

    if not quiz_id:
        return jsonify({
            "success": True,
            "quiz": None
        }), 200

    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor(pymysql.cursors.DictCursor)

        cur.execute("""
            SELECT
                quiz_id,
                DATE_FORMAT(quiz_date, '%%Y-%%m-%%d') AS quiz_date,
                TIME_FORMAT(quiz_start_time, '%%H:%%i') AS quiz_start_time,
                TIME_FORMAT(quiz_end_time, '%%H:%%i') AS quiz_end_time,
                year,
                created_by
            FROM faculty_quiz_master
            WHERE quiz_id = %s
        """, (quiz_id,))

        quiz = cur.fetchone()

        return jsonify({
            "success": True,
            "quiz": quiz
        }), 200

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()   # 🔥 return to pool



@app.route("/api/admin/faculty-quiz/view", methods=["GET", "OPTIONS"])
@admin_token_required
def view_faculty_quiz(admin):

    if request.method == "OPTIONS":
        return jsonify({"success": True}), 200

    quiz_id = request.args.get("quiz_id")

    if not quiz_id:
        return jsonify({
            "success": False,
            "message": "quiz_id required"
        }), 400

    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor(pymysql.cursors.DictCursor)

        # 1️⃣ Quiz Master
        cur.execute("""
            SELECT
                quiz_id,
                DATE_FORMAT(quiz_date, '%%Y-%%m-%%d') AS quiz_date,
                TIME_FORMAT(quiz_start_time, '%%H:%%i') AS quiz_start_time,
                TIME_FORMAT(quiz_end_time, '%%H:%%i') AS quiz_end_time,
                year,
                created_by
            FROM faculty_quiz_master
            WHERE quiz_id = %s
        """, (quiz_id,))

        quiz = cur.fetchone()

        if not quiz:
            return jsonify({
                "success": False,
                "message": "Quiz not found"
            }), 404

        # 2️⃣ Questions
        cur.execute("""
            SELECT
                id,
                question,
                option_a,
                option_b,
                option_c,
                option_d,
                correct_option
            FROM faculty_quiz_questions_new
            WHERE quiz_id = %s
            ORDER BY id
        """, (quiz_id,))

        questions = cur.fetchall()

        return jsonify({
            "success": True,
            "quiz": quiz,
            "questions": questions
        }), 200

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()   # 🔥 return to pool


@app.route("/api/admin/daily-quiz/single-student", methods=["GET"])
@admin_token_required
def admin_daily_quiz_single_student(current_admin):

    uid = request.args.get("uid", type=int)
    year = request.args.get("year", type=int)

    if not uid or year not in (2, 3):
        return jsonify({
            "success": False,
            "message": "uid and valid year required"
        }), 400

    attempts_table = (
        "daily_quiz_attempts_y2"
        if year == 2
        else "daily_quiz_attempts_y3"
    )

    conn = get_db()
    cur = conn.cursor(pymysql.cursors.DictCursor)

    try:
        # STUDENT DETAILS
        cur.execute(
            "SELECT name, email FROM students WHERE uid = %s",
            (uid,)
        )
        student = cur.fetchone()
        if not student:
            return jsonify({
                "success": False,
                "message": "Student not found"
            }), 404

        # DAILY QUIZ MARKS
        cur.execute(
            f"""
            SELECT quiz_date, score, total
            FROM {attempts_table}
            WHERE uid = %s
            ORDER BY quiz_date DESC
            """,
            (uid,)
        )

        records = cur.fetchall()

        # ✅ FIX DATE FORMAT
        for r in records:
            if r["quiz_date"]:
                r["quiz_date"] = r["quiz_date"].strftime("%Y-%m-%d")

        return jsonify({
            "success": True,
            "student": {
                "name": student["name"],
                "email": student["email"]
            },
            "data": records
        }), 200

    finally:
        cur.close()
        conn.close()


@app.route("/api/admin/daily-quiz/full-class", methods=["GET"])
@admin_token_required
def admin_daily_quiz_full_class(current_admin):

    year = request.args.get("year", type=int)
    quiz_date = request.args.get("date")  # YYYY-MM-DD

    if year not in (2, 3) or not quiz_date:
        return jsonify({
            "success": False,
            "message": "year and date required"
        }), 400

    attempts_table = (
        "daily_quiz_attempts_y2"
        if year == 2
        else "daily_quiz_attempts_y3"
    )

    topics_table = (
        "daily_quiz_topics_y2"
        if year == 2
        else "daily_quiz_topics_y3"
    )

    conn = get_db()
    cur = conn.cursor(pymysql.cursors.DictCursor)

    try:
        # ---------------- QUIZ META ----------------
        cur.execute(
            f"""
            SELECT topic, difficulty, total_questions
            FROM {topics_table}
            WHERE quiz_date = %s
            """,
            (quiz_date,)
        )
        quiz = cur.fetchone()

        if not quiz:
            return jsonify({
                "success": False,
                "message": "Quiz not found"
            }), 404

        # ---------------- STUDENTS + MARKS ----------------
        cur.execute(
            f"""
            SELECT
                s.uid,
                s.name,
                a.score AS marks,
                CASE
                    WHEN a.uid IS NULL THEN FALSE
                    ELSE TRUE
                END AS attempted
            FROM students s
            LEFT JOIN {attempts_table} a
                ON s.uid = a.uid
               AND a.quiz_date = %s
            WHERE CAST(s.year AS UNSIGNED) = %s
            ORDER BY s.uid
            """,
            (quiz_date, year)
        )

        students = cur.fetchall()

        return jsonify({
            "success": True,
            "quiz": {
                "date": quiz_date,
                "year": year,
                "topic": quiz["topic"],
                "difficulty": quiz["difficulty"],
                "total_marks": quiz["total_questions"]
            },
            "students": students
        }), 200

    finally:
        cur.close()
        conn.close()


@app.route("/api/faculty/student/quiz-marks", methods=["GET", "OPTIONS"])
@admin_token_required
def student_quiz_wise_marks(current_user):

    # ---------------- CORS ----------------
    if request.method == "OPTIONS":
        return jsonify({"success": True}), 200

    # ---------------- PARAMS ----------------
    uid = request.args.get("uid", type=int)
    year = request.args.get("year", type=int)

    if not uid or year not in (2, 3):
        return jsonify({
            "success": False,
            "message": "uid and valid year (2 or 3) required"
        }), 400

    # ---------------- TABLE ----------------
    marks_table = (
        "assignment_quiz_marks_y2"
        if year == 2
        else "assignment_quiz_marks_y3"
    )

    conn = get_db()
    cur = conn.cursor()  # DictCursor REQUIRED

    try:
        # ==================================================
        # 1️⃣ FETCH STUDENT INFO
        # ==================================================
        cur.execute("""
            SELECT name, email
            FROM students
            WHERE uid = %s
        """, (uid,))
        student = cur.fetchone()

        student_name = (
            student["name"]
            if student and student.get("name")
            else "NOT GIVEN"
        )
        student_email = (
            student["email"]
            if student and student.get("email")
            else "NOT GIVEN"
        )

        # ==================================================
        # 2️⃣ FETCH QUIZ + MARKS (CORRECT JOIN DIRECTION)
        # ==================================================
        cur.execute(f"""
            SELECT
                q.quiz_id,
                q.quiz_date,
                q.quiz_start_time,
                q.quiz_end_time,
                q.created_by,

                m.score,
                m.total_questions

            FROM faculty_quiz_master q
            LEFT JOIN {marks_table} m
                ON q.quiz_id = m.quiz_id
                AND m.uid = %s

            WHERE q.year = %s

            ORDER BY
                q.quiz_date DESC,
                q.quiz_id DESC
        """, (uid, year))

        rows = cur.fetchall()
        data = []

        # ==================================================
        # 3️⃣ FINAL LOGIC
        # ==================================================
        for r in rows:

            # MARKS RULE (IMPORTANT)
            if r["score"] is None:
                marks_value = "NOT GIVEN"
                total_value = None
            else:
                marks_value = r["score"]
                total_value = r["total_questions"]

            data.append({
                "quiz_id": r["quiz_id"],

                # MARKS
                "marks": marks_value,
                "total_marks": total_value,

                # QUIZ INFO (ALWAYS FROM QUIZ MASTER)
                "quiz_date": r["quiz_date"],
                "start_time": (
                    str(r["quiz_start_time"])
                    if r["quiz_start_time"] else None
                ),
                "end_time": (
                    str(r["quiz_end_time"])
                    if r["quiz_end_time"] else None
                ),
                "created_by": r["created_by"],
            })

        # ==================================================
        # 4️⃣ RESPONSE
        # ==================================================
        return jsonify({
            "success": True,
            "uid": uid,
            "year": year,
            "student_name": student_name,
            "email": student_email,
            "total_quizzes": len(data),
            "data": data
        })

    finally:
        cur.close()
        conn.close()

@app.route("/api/faculty/quiz/marks", methods=["GET", "OPTIONS"])
@admin_token_required
def particular_quiz_marks(current_user):

    if request.method == "OPTIONS":
        return jsonify({"success": True}), 200

    quiz_id = request.args.get("quiz_id", type=int)
    year = request.args.get("year", type=int)

    if not quiz_id or year not in (2, 3):
        return jsonify({
            "success": False,
            "message": "quiz_id and valid year (2 or 3) required"
        }), 400

    marks_table = (
        "assignment_quiz_marks_y2"
        if year == 2
        else "assignment_quiz_marks_y3"
    )

    conn = get_db()
    cur = conn.cursor()  # DictCursor REQUIRED

    try:
        # =========================
        # QUIZ DETAILS
        # =========================
        cur.execute("""
            SELECT quiz_date, quiz_start_time, quiz_end_time, created_by
            FROM faculty_quiz_master
            WHERE quiz_id = %s AND year = %s
        """, (quiz_id, year))

        quiz = cur.fetchone()

        if not quiz:
            return jsonify({
                "success": False,
                "message": "Quiz not found"
            }), 404

        # =========================
        # STUDENTS + MARKS
        # =========================
        cur.execute(f"""
            SELECT
                s.uid,
                s.name,

                m.score,
                m.total_questions

            FROM students s
            LEFT JOIN {marks_table} m
                ON s.uid = m.uid
                AND m.quiz_id = %s

            WHERE s.year = %s
            ORDER BY s.uid ASC
        """, (quiz_id, year))

        rows = cur.fetchall()
        data = []

        for r in rows:
            if r["score"] is None:
                marks = "NOT GIVEN"
                total = None
            else:
                marks = r["score"]
                total = r["total_questions"]

            data.append({
                "uid": r["uid"],
                "name": r["name"],
                "marks": marks,
                "total_marks": total
            })

        return jsonify({
            "success": True,
            "quiz_id": quiz_id,
            "year": year,
            "quiz_date": quiz["quiz_date"],
            "start_time": str(quiz["quiz_start_time"]) if quiz["quiz_start_time"] else None,
            "end_time": str(quiz["quiz_end_time"]) if quiz["quiz_end_time"] else None,
            "created_by": quiz["created_by"],
            "total_students": len(data),
            "data": data
        })

    finally:
        cur.close()
        conn.close()


@app.route("/api/admin/leaderboard/daily", methods=["GET", "OPTIONS"])
@admin_token_required
def admin_daily_quiz_leaderboard(current_user):

    if request.method == "OPTIONS":
        return jsonify({"success": True}), 200

    year = request.args.get("year")
    lb_type = request.args.get("type", "all")
    month = request.args.get("month")

    if year not in ["2", "3"]:
        return jsonify({"success": False, "message": "Invalid year"}), 400

    if lb_type not in ["month", "all"]:
        return jsonify({"success": False, "message": "Invalid type"}), 400

    attempts_table = (
        "daily_quiz_attempts_y2"
        if year == "2"
        else "daily_quiz_attempts_y3"
    )

    date_filter = ""
    params = [year]

    if lb_type == "month":
        if not month:
            return jsonify({"success": False, "message": "Month required"}), 400
        date_filter = "AND MONTH(a.quiz_date) = %s"
        params.append(month)

    conn = get_db()
    cur = conn.cursor(pymysql.cursors.DictCursor)

    cur.execute(f"""
        SELECT
            s.uid,
            s.name,
            SUM(a.score) AS total_marks,
            SUM(a.total) AS total_out_of
        FROM {attempts_table} a
        JOIN students s ON s.uid = a.uid
        WHERE s.year = %s
        {date_filter}
        GROUP BY s.uid, s.name
        ORDER BY total_marks DESC
    """, params)

    rows = cur.fetchall()

    cur.close()
    conn.close()

    return jsonify({
        "success": True,
        "data": rows
    }), 200


# ============================================================
# RUN SERVER
# ============================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port)

