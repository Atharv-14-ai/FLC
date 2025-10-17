
# app.py (complete, session-based auth, role-based access control)
from functools import wraps
import os
from datetime import datetime
from collections import defaultdict

from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect, url_for, session, flash
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import logging

# Load .env if present
load_dotenv()

# --- App config ---
app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev_secret_key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL",
    "postgresql://postgres:1234@localhost:5432/flc"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# --- Logging (debug friendly) ---
logging.basicConfig(level=logging.DEBUG)
app.logger.setLevel(logging.DEBUG)

# --- Extensions ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# --- Models ---
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(30), nullable=False)  # 'Supplier', 'Intermediate', 'End User'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"

class DispatchData(db.Model):
    __tablename__ = "dispatch_data"
    id = db.Column(db.Integer, primary_key=True)

    from_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    to_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    # Add dispatch type and parent link
    dispatch_type = db.Column(db.String(20), nullable=False, default="empty")  # 'empty' or 'filled'
    parent_dispatch_id = db.Column(db.Integer, db.ForeignKey("dispatch_data.id"), nullable=True)

    from_role = db.Column(db.String(30), nullable=False)
    to_role = db.Column(db.String(30), nullable=False)
    component = db.Column(db.String(100), nullable=False)
    flc_qty = db.Column(db.Integer, nullable=False)
    component_qty = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(30), default="Pending")
    remarks = db.Column(db.String(500), nullable=True)
    date_time = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    sender = db.relationship("User", foreign_keys=[from_user_id], backref="dispatches_sent", lazy=True)
    receiver = db.relationship("User", foreign_keys=[to_user_id], backref="dispatches_received", lazy=True)

    # self-referential parent-child relationship
    parent = db.relationship("DispatchData", remote_side=[id], backref="children", lazy=True)

    def __repr__(self):
        return f"<Dispatch {self.id} {self.from_role}->{self.to_role} ({self.dispatch_type}) x{self.flc_qty}>"

class Returned(db.Model):
    __tablename__ = "returned"
    id = db.Column(db.Integer, primary_key=True)
    dispatch_id = db.Column(db.Integer, db.ForeignKey("dispatch_data.id"), nullable=False)
    from_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    to_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    flc_qty = db.Column(db.Integer, nullable=False)
    remarks = db.Column(db.String(500), nullable=True)
    date_time = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Return {self.id} dispatch:{self.dispatch_id} x{self.flc_qty}>"

# --- Components list (example). Replace/fetch from DB when ready ---
COMPONENTS = ["Oil Pan", "Engine Block", "Gearbox", "Suspension Kit", "Brake Assembly"]

# ---------- AUTH / ROLE DECORATORS ----------
def login_required(f):
    """Simple session-based login_required decorator."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    """Restrict a route to one or more allowed roles (works with session['role'])."""
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_role = session.get("role")
            if user_role not in roles:
                flash("Access denied for your role.", "danger")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

# ------------------- AUTH ROUTES -------------------
@app.route("/", methods=["GET", "POST"])
def login():
    # If already logged in, go to dashboard
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        app.logger.debug("Login form data: %s", dict(request.form))
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            # set session
            session["user_id"] = user.id
            session["role"] = user.role
            session["username"] = user.username
            flash("Logged in successfully", "success")
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid username or password"
            app.logger.debug("Login failed for user=%s", username)
    return render_template("index.html", error=error)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        app.logger.debug("Signup form data: %s", dict(request.form))
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "").strip()
        if not username or not password or not role:
            error = "All fields required."
        elif User.query.filter_by(username=username).first():
            error = "Username already exists."
        else:
            hashed = bcrypt.generate_password_hash(password).decode("utf-8")
            u = User(username=username, password=hashed, role=role)
            db.session.add(u)
            db.session.commit()
            flash("User created — please login.", "success")
            return redirect(url_for("login"))
    return render_template("signup.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for("login"))

# ------------------- DASHBOARD -------------------
@app.route('/dashboard')
@login_required
def dashboard():
    role = session.get('role')
    username = session.get('username')

    if role == 'Supplier':
        # Supplier: Dispatches sent to B + Returns received (to Supplier)
        sent_dispatches = DispatchData.query.filter_by(from_role='Supplier').order_by(DispatchData.date_time.desc()).all()
        received_returns = Returned.query.filter_by(to_user_id=session.get("user_id")).order_by(Returned.date_time.desc()).all()
        return render_template(
            'dashboard.html',
            role=role,
            sent_dispatches=sent_dispatches,
            received_returns=received_returns
        )

    elif role == 'Intermediate':
        # Intermediate: Receives from A + Sends to C
        received_dispatches = DispatchData.query.filter_by(to_role='Intermediate').order_by(DispatchData.date_time.desc()).all()
        sent_dispatches = DispatchData.query.filter_by(from_role='Intermediate').order_by(DispatchData.date_time.desc()).all()
        return render_template(
            'dashboard.html',
            role=role,
            received_dispatches=received_dispatches,
            sent_dispatches=sent_dispatches
        )

    else:
        flash("Invalid role session. Please log in again.", "danger")
        return redirect(url_for('logout'))

# ------------------- DISPATCH CREATE -------------------
# @app.route('/dispatch_create', methods=['GET', 'POST'])
# @login_required
# @role_required('Supplier', 'Intermediate')
# def dispatch_create():
#     current_user_id = session["user_id"]
#     current_user = User.query.get(current_user_id)
#     if not current_user:
#         flash("Invalid session user. Please login again.", "danger")
#         return redirect(url_for("logout"))

#     role = current_user.role
#     error = None
#     receiver_candidates = []
#     end_users = []
#     parent_dispatches = []

#     # If Supplier: list Intermediate users to send empties to.
#     # If Intermediate: list potential End Users + list of A->B empty dispatches received (as parents).
#     if role == "Supplier":
#         receiver_candidates = User.query.filter_by(role="Intermediate").order_by(User.username).all()
#     elif role == "Intermediate":
#         end_users = User.query.filter_by(role="End User").order_by(User.username).all()
#         # Candidate parent A->B empty dispatches that are Received and still have empties available
#         empties = DispatchData.query.filter_by(to_user_id=current_user_id, dispatch_type="empty", status="Received").all()
#         for d in empties:
#             consumed = db.session.query(db.func.coalesce(db.func.sum(DispatchData.flc_qty), 0)).filter(DispatchData.parent_dispatch_id == d.id).scalar() or 0
#             available = d.flc_qty - consumed
#             if available > 0:
#                 parent_dispatches.append((d, available))

#     if request.method == "POST":
#         app.logger.debug("Dispatch create form data: %s", dict(request.form))
#         try:
#             component = request.form.get("component", "").strip()
#             flc_qty = int(request.form.get("flc_qty", "0"))
#             component_qty = int(request.form.get("component_qty", "0"))
#             remarks = request.form.get("remarks", "").strip()
#         except ValueError:
#             error = "Quantities must be integers."

#         if not error and (not component or flc_qty <= 0 or component_qty <= 0):
#             error = "Please provide component and positive quantities."

#         if not error:
#             if role == "Supplier":
#                 try:
#                     to_user_id = int(request.form.get("to_user_id"))
#                 except Exception:
#                     error = "Select a valid Intermediate to send empties to."
#                     return render_template("dispatch_create.html", role=role, receiver_candidates=receiver_candidates, error=error)

#                 to_user = User.query.get(to_user_id)
#                 if not to_user or to_user.role != "Intermediate":
#                     error = "Selected receiver is not an Intermediate user."
#                     return render_template("dispatch_create.html", role=role, receiver_candidates=receiver_candidates, error=error)

#                 new_dispatch = DispatchData(
#                     from_user_id=current_user_id,
#                     to_user_id=to_user_id,
#                     dispatch_type="empty",
#                     parent_dispatch_id=None,
#                     from_role=current_user.role,
#                     to_role=to_user.role,
#                     component=component,
#                     flc_qty=flc_qty,
#                     component_qty=component_qty,
#                     status="Pending",
#                     remarks=remarks,
#                     date_time=datetime.utcnow()
#                 )
#                 try:
#                     db.session.add(new_dispatch)
#                     db.session.commit()
#                     flash(f"Empty dispatch created (ID: {new_dispatch.id})", "success")
#                     return redirect(url_for("dispatch_create"))
#                 except Exception as e:
#                     db.session.rollback()
#                     app.logger.exception("Failed to create supplier dispatch")
#                     error = f"DB error: {e}"

#             elif role == "Intermediate":
#                 parent_id_raw = request.form.get("parent_dispatch_id", "").strip()
#                 to_user_raw = request.form.get("to_user_id", "").strip()  # can be existing user id or 'other'

#                 if to_user_raw == "other":
#                     end_user_name = request.form.get("end_user_name", "").strip()
#                     if not end_user_name:
#                         error = "Please enter End User name when selecting Other."
#                         return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)
#                     to_user = User.query.filter_by(username=end_user_name, role="End User").first()
#                     if not to_user:
#                         dummy_pw = bcrypt.generate_password_hash(os.urandom(16)).decode("utf-8")
#                         try:
#                             to_user = User(username=end_user_name, password=dummy_pw, role="End User")
#                             db.session.add(to_user)
#                             db.session.commit()
#                         except Exception as e:
#                             db.session.rollback()
#                             app.logger.exception("Failed to create End User")
#                             error = f"Failed to create End User: {e}"
#                             return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)
#                     to_user_id = to_user.id
#                 else:
#                     try:
#                         to_user_id = int(to_user_raw)
#                     except Exception:
#                         error = "Select a valid End User."
#                         return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)
#                     to_user = User.query.get(to_user_id)
#                     if not to_user or to_user.role != "End User":
#                         error = "Selected receiver must be an End User."
#                         return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)

#                 if not parent_id_raw:
#                     error = "Select which empty dispatch (A→B) batch you are consuming."
#                     return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)

#                 try:
#                     parent_id = int(parent_id_raw)
#                 except Exception:
#                     error = "Invalid parent dispatch selected."
#                     return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)

#                 parent = DispatchData.query.get(parent_id)
#                 if not parent or parent.to_user_id != current_user_id or parent.dispatch_type != "empty" or parent.status != "Received":
#                     error = "Selected parent dispatch is not valid (must be an A→B empty dispatch received by you)."
#                     return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)

#                 consumed_on_parent = db.session.query(db.func.coalesce(db.func.sum(DispatchData.flc_qty), 0)).filter(DispatchData.parent_dispatch_id == parent.id).scalar() or 0
#                 available = parent.flc_qty - consumed_on_parent
#                 if flc_qty > available:
#                     error = f"Cannot dispatch {flc_qty} FLCs — only {available} empties available from parent dispatch {parent.id}."
#                     return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)

#                 new_dispatch = DispatchData(
#                     from_user_id=current_user_id,
#                     to_user_id=to_user_id,
#                     dispatch_type="filled",
#                     parent_dispatch_id=parent.id,
#                     from_role=current_user.role,
#                     to_role=to_user.role,
#                     component=component,
#                     flc_qty=flc_qty,
#                     component_qty=component_qty,
#                     status="Pending",
#                     remarks=remarks,
#                     date_time=datetime.utcnow()
#                 )
#                 try:
#                     db.session.add(new_dispatch)
#                     db.session.commit()
#                     flash(f"Filled dispatch created to End User (ID: {new_dispatch.id})", "success")
#                     return redirect(url_for("dispatch_create"))
#                 except Exception as e:
#                     db.session.rollback()
#                     app.logger.exception("Failed to create filled dispatch")
#                     error = f"DB error: {e}"
#             else:
#                 error = "Your role cannot create dispatches here."

#     # Render form depending on role
#     if role == "Supplier":
#         return render_template("dispatch_create.html", role=role, receiver_candidates=receiver_candidates, error=error)
#     elif role == "Intermediate":
#         return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)
#     else:
#         flash("You don't have permissions to create dispatches.", "warning")
#         return redirect(url_for("dashboard"))



@app.route('/dispatch_create', methods=['GET', 'POST'])
@login_required
@role_required('Supplier', 'Intermediate')
def dispatch_create():
    current_user_id = session["user_id"]
    current_user = User.query.get(current_user_id)
    if not current_user:
        flash("Invalid session user. Please login again.", "danger")
        return redirect(url_for("logout"))

    role = current_user.role
    error = None
    receiver_candidates = []
    end_users = []
    parent_dispatches = []

    # If Supplier: list Intermediate users to send empties to.
    # If Intermediate: list potential End Users + list of A->B empty dispatches received (as parents).
    if role == "Supplier":
        receiver_candidates = User.query.filter_by(role="Intermediate").order_by(User.username).all()
    elif role == "Intermediate":
        end_users = User.query.filter_by(role="End User").order_by(User.username).all()
        # Candidate parent A->B empty dispatches that are Received and still have empties available
        empties = DispatchData.query.filter_by(to_user_id=current_user_id, dispatch_type="empty", status="Received").all()
        for d in empties:
            consumed = db.session.query(db.func.coalesce(db.func.sum(DispatchData.flc_qty), 0)).filter(DispatchData.parent_dispatch_id == d.id).scalar() or 0
            available = d.flc_qty - consumed
            if available > 0:
                parent_dispatches.append((d, available))

    if request.method == "POST":
        app.logger.debug("Dispatch create form data: %s", dict(request.form))
        try:
            component = request.form.get("component", "").strip()
            flc_qty = int(request.form.get("flc_qty", "0"))
            component_qty = int(request.form.get("component_qty", "0"))
            remarks = request.form.get("remarks", "").strip()
        except ValueError:
            error = "Quantities must be integers."

        if not error and (not component or flc_qty <= 0 or component_qty <= 0):
            error = "Please provide component and positive quantities."

        if not error:
            if role == "Supplier":
                try:
                    to_user_id = int(request.form.get("to_user_id"))
                except Exception:
                    error = "Select a valid Intermediate to send empties to."
                    return render_template("dispatch_create.html", role=role, receiver_candidates=receiver_candidates, error=error)

                to_user = User.query.get(to_user_id)
                if not to_user or to_user.role != "Intermediate":
                    error = "Selected receiver is not an Intermediate user."
                    return render_template("dispatch_create.html", role=role, receiver_candidates=receiver_candidates, error=error)

                new_dispatch = DispatchData(
                    from_user_id=current_user_id,
                    to_user_id=to_user_id,
                    dispatch_type="empty",
                    parent_dispatch_id=None,
                    from_role=current_user.role,
                    to_role=to_user.role,
                    component=component,
                    flc_qty=flc_qty,
                    component_qty=component_qty,
                    status="Pending",
                    remarks=remarks,
                    date_time=datetime.utcnow()
                )
                try:
                    db.session.add(new_dispatch)
                    db.session.commit()
                    flash(f"Empty dispatch created (ID: {new_dispatch.id})", "success")
                    return redirect(url_for("dispatch_create"))
                except Exception as e:
                    db.session.rollback()
                    app.logger.exception("Failed to create supplier dispatch")
                    error = f"DB error: {e}"

            elif role == "Intermediate":
                parent_id_raw = request.form.get("parent_dispatch_id", "").strip()
                to_user_raw = request.form.get("to_user_id", "").strip()  # can be existing user id or 'other'

                if to_user_raw == "other":
                    end_user_name = request.form.get("end_user_name", "").strip()
                    if not end_user_name:
                        error = "Please enter End User name when selecting Other."
                        return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)
                    to_user = User.query.filter_by(username=end_user_name, role="End User").first()
                    if not to_user:
                        dummy_pw = bcrypt.generate_password_hash(os.urandom(16)).decode("utf-8")
                        try:
                            to_user = User(username=end_user_name, password=dummy_pw, role="End User")
                            db.session.add(to_user)
                            db.session.commit()
                        except Exception as e:
                            db.session.rollback()
                            app.logger.exception("Failed to create End User")
                            error = f"Failed to create End User: {e}"
                            return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)
                    to_user_id = to_user.id
                else:
                    try:
                        to_user_id = int(to_user_raw)
                    except Exception:
                        error = "Select a valid End User."
                        return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)
                    to_user = User.query.get(to_user_id)
                    if not to_user or to_user.role != "End User":
                        error = "Selected receiver must be an End User."
                        return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)

                if not parent_id_raw:
                    error = "Select which empty dispatch (A→B) batch you are consuming."
                    return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)

                try:
                    parent_id = int(parent_id_raw)
                except Exception:
                    error = "Invalid parent dispatch selected."
                    return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)

                parent = DispatchData.query.get(parent_id)
                if not parent or parent.to_user_id != current_user_id or parent.dispatch_type != "empty" or parent.status != "Received":
                    error = "Selected parent dispatch is not valid (must be an A→B empty dispatch received by you)."
                    return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)

                consumed_on_parent = db.session.query(db.func.coalesce(db.func.sum(DispatchData.flc_qty), 0)).filter(DispatchData.parent_dispatch_id == parent.id).scalar() or 0
                available = parent.flc_qty - consumed_on_parent
                if flc_qty > available:
                    error = f"Cannot dispatch {flc_qty} FLCs — only {available} empties available from parent dispatch {parent.id}."
                    return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)

                # ✅ Mark dispatch to End User as Delivered directly
                new_dispatch = DispatchData(
                    from_user_id=current_user_id,
                    to_user_id=to_user_id,
                    dispatch_type="filled",
                    parent_dispatch_id=parent.id,
                    from_role=current_user.role,
                    to_role=to_user.role,
                    component=component,
                    flc_qty=flc_qty,
                    component_qty=component_qty,
                    status="Delivered",  # CHANGED from Pending → Delivered
                    remarks=remarks,
                    date_time=datetime.utcnow()
                )
                try:
                    db.session.add(new_dispatch)
                    db.session.commit()
                    flash(f"Filled dispatch created to End User (ID: {new_dispatch.id}) and marked as Delivered.", "success")
                    return redirect(url_for("dispatch_create"))
                except Exception as e:
                    db.session.rollback()
                    app.logger.exception("Failed to create filled dispatch")
                    error = f"DB error: {e}"
            else:
                error = "Your role cannot create dispatches here."

    # Render form depending on role
    if role == "Supplier":
        return render_template("dispatch_create.html", role=role, receiver_candidates=receiver_candidates, error=error)
    elif role == "Intermediate":
        return render_template("dispatch_create.html", role=role, end_users=end_users, parent_dispatches=parent_dispatches, error=error)
    else:
        flash("You don't have permissions to create dispatches.", "warning")
        return redirect(url_for("dashboard"))


# ------------------- RECEIVE -------------------
@app.route("/dispatch_receive", methods=["GET", "POST"])
@login_required
@role_required('Supplier', 'Intermediate')
def dispatch_receive():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    role = session.get("role")
    error = None
    if request.method == "POST":
        app.logger.debug("Receive form data: %s", dict(request.form))
        try:
            dispatch_id = int(request.form.get("dispatch_id"))
        except Exception:
            error = "Invalid dispatch id."
            return render_template("dispatch_receive.html", dispatches=[], error=error)
        dispatch = DispatchData.query.get(dispatch_id)
        if not dispatch:
            error = "Dispatch not found."
        elif dispatch.to_role != role:
            error = "You are not authorized to receive this dispatch (role mismatch)."
        else:
            dispatch.status = "Received"
            db.session.commit()
            flash(f"Dispatch {dispatch_id} marked Received.", "success")
            return redirect(url_for("dispatch_receive"))

    # show dispatches targeted to user's role
    dispatches = DispatchData.query.filter_by(to_role=role).order_by(DispatchData.date_time.desc()).all()
    return render_template("dispatch_receive.html", dispatches=dispatches, error=error)

# ------------------- RETURNS -------------------
@app.route('/returns', methods=['GET', 'POST'])
@login_required
@role_required('Supplier')
def returns():
    current_user_id = session["user_id"]
    current_user = User.query.get(current_user_id)

    if not current_user or current_user.role != 'Supplier':
        flash("Only suppliers can record returns.", "danger")
        return redirect(url_for('dashboard'))

    # POST: record a return
    if request.method == 'POST':
        try:
            dispatch_id = int(request.form.get('dispatch_id', 0))
            flc_qty = int(request.form.get('flc_qty', 0))
            remarks = request.form.get('remarks', '').strip()

            dispatch = DispatchData.query.get(dispatch_id)
            if not dispatch:
                flash("Invalid dispatch selected.", "danger")
                return redirect(url_for('returns'))

            # Compute how many FLCs are still available to return (based on that dispatch)
            total_returned = db.session.query(
                db.func.coalesce(db.func.sum(Returned.flc_qty), 0)
            ).filter_by(dispatch_id=dispatch_id).scalar() or 0

            remaining = dispatch.flc_qty - total_returned
            if remaining <= 0:
                flash("All FLCs from this dispatch have already been returned.", "info")
                return redirect(url_for('returns'))

            if flc_qty <= 0:
                flash("Returned quantity must be positive.", "warning")
                return redirect(url_for('returns'))

            if flc_qty > remaining:
                flash(f"Cannot return {flc_qty} FLCs — only {remaining} available.", "danger")
                return redirect(url_for('returns'))

            # Record return
            new_return = Returned(
                dispatch_id=dispatch.id,
                from_user_id=current_user.id,
                to_user_id=dispatch.from_user_id,  # supplier receives back
                flc_qty=flc_qty,
                remarks=remarks,
                date_time=datetime.utcnow()
            )
            db.session.add(new_return)

            # Update dispatch status if all FLCs returned
            if flc_qty == remaining:
                dispatch.status = "Returned"

            db.session.commit()
            flash(f"Return of {flc_qty} FLCs recorded successfully.", "success")
            return redirect(url_for('returns'))

        except Exception as e:
            db.session.rollback()
            app.logger.exception("Error recording return")
            flash(f"Failed to record return: {str(e)}", "danger")
            return redirect(url_for('returns'))

    # GET: dispatches eligible for return (dispatched to End User and Received)
    dispatches = DispatchData.query.filter_by(to_role="End User", status="Received").order_by(DispatchData.date_time.desc()).all()
    # All returns (for listing in the template)
    all_returns = Returned.query.order_by(Returned.date_time.desc()).all()
    return render_template('returns.html', dispatches=dispatches, returns=all_returns)

# ------------------- REPORTS -------------------
# @app.route("/reports")
# @login_required
# def reports():
#     cycle_report = DispatchData.query.order_by(DispatchData.id.desc()).all()
#     component_data = defaultdict(lambda: {"flc_qty": 0, "component_qty": 0})
#     for d in DispatchData.query.all():
#         component_data[d.component]["flc_qty"] += d.flc_qty
#         component_data[d.component]["component_qty"] += d.component_qty

#     received_dispatches = DispatchData.query.filter_by(status="Received").all()
#     returned_dispatch_ids = {r.dispatch_id for r in Returned.query.all()}
#     pending_returns = [d for d in received_dispatches if d.id not in returned_returns_ids()] if False else None

#     # (Simpler: pending returns are received dispatches whose id is not present in Returned.dispatch_id)
#     returned_dispatch_ids = {r.dispatch_id for r in Returned.query.all()}
#     pending_returns = [d for d in received_dispatches if d.id not in returned_dispatch_ids]

#     remarks_list = []
#     for d in DispatchData.query.filter(DispatchData.remarks != None).all():
#         if d.remarks and d.remarks.strip():
#             remarks_list.append({"id": d.id, "type": "Dispatch", "remarks": d.remarks})
#     for r in Returned.query.filter(Returned.remarks != None).all():
#         if r.remarks and r.remarks.strip():
#             remarks_list.append({"id": r.id, "type": "Return", "remarks": r.remarks})

#     return render_template("reports.html",
#                            cycle_report=cycle_report,
#                            component_report=component_data,
#                            pending_returns=pending_returns,
#                            remarks=remarks_list)


# ---------- Replace your existing /reports route with this ----------
@app.route("/reports")
@login_required
def reports():
    user_id = session.get("user_id")
    role = session.get("role")

    cycle_report = []
    pending_returns = []
    remarks_list = []

    if role == "Supplier":
        # ---------------- Supplier View ----------------
        supplier_dispatches = (
            DispatchData.query
            .filter_by(from_user_id=user_id, dispatch_type="empty")
            .order_by(DispatchData.date_time.desc())
            .all()
        )

        for d in supplier_dispatches:
            # Returns related to these dispatches (A→B)
            returned_qty = (
                db.session.query(db.func.coalesce(db.func.sum(Returned.flc_qty), 0))
                .filter(Returned.dispatch_id == d.id, Returned.to_user_id == user_id)
                .scalar()
                or 0
            )
            pending_qty = max(0, (d.flc_qty or 0) - returned_qty)

            cycle_report.append({
                "id": d.id,
                "from_user": d.sender.username if d.sender else "-",
                "to_user": d.receiver.username if d.receiver else "-",
                "component": d.component,
                "flc_qty": d.flc_qty or 0,
                "component_qty": d.component_qty or 0,
                "returned_qty": returned_qty,
                "pending_qty": pending_qty,
                "status": d.status,
                "date_time": d.date_time
            })

            if pending_qty > 0:
                pending_returns.append({
                    "id": d.id,
                    "from_user": d.sender.username if d.sender else "-",
                    "to_user": d.receiver.username if d.receiver else "-",
                    "flc_qty": d.flc_qty or 0,
                    "returned_qty": returned_qty,
                    "pending_qty": pending_qty
                })

            if d.remarks:
                remarks_list.append({"id": d.id, "type": "Dispatch", "remarks": d.remarks})

        supplier_returns = (
            Returned.query
            .filter_by(to_user_id=user_id)
            .order_by(Returned.date_time.desc())
            .all()
        )
        for r in supplier_returns:
            if r.remarks:
                remarks_list.append({"id": r.id, "type": "Return", "remarks": r.remarks})

    elif role == "Intermediate":
        # ---------------- Intermediate View ----------------
        # Received from Supplier (A→B)
        received_from_supplier = (
            DispatchData.query
            .filter_by(to_user_id=user_id, dispatch_type="empty")
            .order_by(DispatchData.date_time.desc())
            .all()
        )

        # Sent to End User (B→C)
        sent_to_enduser = (
            DispatchData.query
            .filter_by(from_user_id=user_id, dispatch_type="filled")
            .order_by(DispatchData.date_time.desc())
            .all()
        )

        all_dispatches = received_from_supplier + sent_to_enduser

        for d in all_dispatches:
            cycle_report.append({
                "id": d.id,
                "from_user": d.sender.username if d.sender else "-",
                "to_user": d.receiver.username if d.receiver else "-",
                "component": d.component,
                "flc_qty": d.flc_qty or 0,
                "component_qty": d.component_qty or 0,
                "returned_qty": 0,
                "pending_qty": 0,
                "status": d.status,
                "date_time": d.date_time
            })
            if d.remarks:
                remarks_list.append({"id": d.id, "type": "Dispatch", "remarks": d.remarks})

        # Returns sent to Supplier
        returns_to_supplier = (
            Returned.query
            .filter_by(from_user_id=user_id)
            .order_by(Returned.date_time.desc())
            .all()
        )
        for r in returns_to_supplier:
            if r.remarks:
                remarks_list.append({"id": r.id, "type": "Return", "remarks": r.remarks})

    else:
        # ---------------- Admin View ----------------
        all_dispatches = DispatchData.query.order_by(DispatchData.id.desc()).all()
        for d in all_dispatches:
            cycle_report.append({
                "id": d.id,
                "from_user": d.sender.username if d.sender else "-",
                "to_user": d.receiver.username if d.receiver else "-",
                "component": d.component,
                "flc_qty": d.flc_qty or 0,
                "component_qty": d.component_qty or 0,
                "returned_qty": 0,
                "pending_qty": 0,
                "status": d.status,
                "date_time": d.date_time
            })

    return render_template(
        "reports.html",
        cycle_report=cycle_report,
        pending_returns=pending_returns,
        remarks=remarks_list,
        role=role
    )




# ------------------- DB INIT & RUN -------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
