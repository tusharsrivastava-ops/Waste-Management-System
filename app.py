import os, re, uuid
from datetime import datetime
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

load_dotenv()
BASE = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config.update(SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-secret'),
                  SQLALCHEMY_DATABASE_URI='sqlite:///' + os.path.join(BASE, 'database.db'),
                  UPLOAD_FOLDER=os.path.join(BASE, 'uploads'), MAX_CONTENT_LENGTH=5 * 1024 * 1024)
db = SQLAlchemy(app)

CATS = ['Plastic', 'Paper', 'Glass', 'Metal', 'Organic', 'Electronic Waste', 'Hazardous Waste', 'Other']
STATUSES = ['Pending', 'Assigned', 'In Progress', 'Collected', 'Completed', 'Rejected']
COLLECTOR_STATUSES = ['In Progress', 'Collected', 'Completed']
EXT = {'png', 'jpg', 'jpeg', 'gif', 'webp'}


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(15))
    address = db.Column(db.String(200))
    city = db.Column(db.String(80))
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='citizen')
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.String(20), unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    waste_type = db.Column(db.String(80))
    category = db.Column(db.String(40))
    quantity = db.Column(db.Float, default=0)
    location = db.Column(db.String(200))
    description = db.Column(db.Text)
    image = db.Column(db.String(200))
    pickup_date = db.Column(db.String(20))
    pickup_time = db.Column(db.String(20))
    status = db.Column(db.String(20), default='Pending')
    collector_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user = db.relationship('User', foreign_keys=[user_id])
    collector = db.relationship('User', foreign_keys=[collector_id])

    def to_dict(self):
        return dict(id=self.id, report_id=self.report_id, waste_type=self.waste_type, category=self.category,
                    quantity=self.quantity, location=self.location, status=self.status,
                    collector=self.collector.full_name if self.collector else None)


def cur():
    return db.session.get(User, session['uid']) if session.get('uid') else None


def need(*roles):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            u = cur()
            if not u:
                return redirect(url_for('login'))
            if roles and u.role not in roles:
                abort(403)
            return f(*a, **k)
        return w
    return deco


@app.context_processor
def inject():
    return dict(me=cur(), CATS=CATS, STATUSES=STATUSES)


@app.route('/')
def index():
    s = dict(collected=db.session.query(db.func.sum(Report.quantity)).filter(Report.status.in_(['Collected', 'Completed'])).scalar() or 0,
             users=User.query.count(), resolved=Report.query.filter_by(status='Completed').count())
    return render_template('index.html', s=s)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        f = {k: request.form.get(k, '').strip() for k in ['full_name', 'email', 'phone', 'address', 'city', 'role']}
        pw, cpw = request.form.get('password', ''), request.form.get('confirm', '')
        err = []
        if not all(f[k] for k in ['full_name', 'email', 'phone', 'address', 'city']): err.append('All fields are required.')
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', f['email']): err.append('Invalid email format.')
        if not re.match(r'^\+?\d{10,13}$', f['phone']): err.append('Phone must be 10-13 digits.')
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$', pw):
            err.append('Password needs 8+ chars with upper, lower, number and symbol.')
        if pw != cpw: err.append('Passwords do not match.')
        if f['role'] not in ('citizen', 'collector'): err.append('Admin accounts are created by an existing admin.')
        if User.query.filter_by(email=f['email'].lower()).first(): err.append('Email already registered.')
        if err:
            for e in err: flash(e, 'danger')
            return render_template('auth.html', mode='register', f=f)
        db.session.add(User(**{**f, 'email': f['email'].lower()}, password_hash=generate_password_hash(pw)))
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('auth.html', mode='register', f={})


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = User.query.filter_by(email=request.form.get('email', '').strip().lower()).first()
        if u and u.active and check_password_hash(u.password_hash, request.form.get('password', '')):
            session.clear()
            session['uid'] = u.id
            session.permanent = bool(request.form.get('remember'))
            return redirect(url_for('dashboard'))
        flash('Incorrect email or password.', 'danger')
    return render_template('auth.html', mode='login', f={})


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/dashboard')
@need()
def dashboard():
    u = cur()
    q = Report.query
    if u.role == 'citizen': q = q.filter_by(user_id=u.id)
    elif u.role == 'collector': q = q.filter_by(collector_id=u.id)
    base = q
    s, st, cat = request.args.get('q', ''), request.args.get('status', ''), request.args.get('category', '')
    if s: q = q.filter(Report.report_id.contains(s) | Report.location.contains(s) | Report.waste_type.contains(s))
    if st: q = q.filter_by(status=st)
    if cat: q = q.filter_by(category=cat)
    reports = q.order_by(Report.created_at.desc()).all()
    cnt = lambda *x: base.filter(Report.status.in_(x)).count()
    stats = dict(total=base.count(), pending=cnt('Pending', 'Assigned'), collected=cnt('Collected', 'Completed'),
                 resolved=cnt('Completed'), today=base.filter_by(pickup_date=datetime.now().strftime('%Y-%m-%d')).count())
    extra = {}
    if u.role == 'admin':
        allr = Report.query
        extra = dict(users=User.query.order_by(User.id).all(), collectors=User.query.filter_by(role='collector', active=True).all(),
                     n_users=User.query.count(), kg=allr.with_entities(db.func.sum(Report.quantity)).filter(Report.status.in_(['Collected', 'Completed'])).scalar() or 0,
                     by_status={x: allr.filter_by(status=x).count() for x in STATUSES},
                     by_cat={x: allr.filter_by(category=x).count() for x in CATS})
        rec = ['Plastic', 'Paper', 'Glass', 'Metal']
        extra['recycled'] = allr.with_entities(db.func.sum(Report.quantity)).filter(Report.category.in_(rec), Report.status.in_(['Collected', 'Completed'])).scalar() or 0
    elif u.role == 'collector':
        extra['collectors'] = []
    return render_template('dashboard.html', reports=reports, stats=stats, x=extra)


@app.route('/report/new', methods=['POST'])
@need('citizen')
def new_report():
    f = request.form
    if not all(f.get(k, '').strip() for k in ['waste_type', 'category', 'quantity', 'location']) or f['category'] not in CATS:
        flash('Please fill all required fields.', 'danger')
        return redirect(url_for('dashboard'))
    try: qty = float(f['quantity']); assert qty > 0
    except Exception:
        flash('Quantity must be a positive number.', 'danger')
        return redirect(url_for('dashboard'))
    fname = None
    img = request.files.get('image')
    if img and img.filename:
        if img.filename.rsplit('.', 1)[-1].lower() not in EXT:
            flash('Invalid image type.', 'danger')
            return redirect(url_for('dashboard'))
        fname = uuid.uuid4().hex[:8] + '_' + secure_filename(img.filename)
        img.save(os.path.join(app.config['UPLOAD_FOLDER'], fname))
    r = Report(report_id='WR-' + uuid.uuid4().hex[:6].upper(), user_id=cur().id, waste_type=f['waste_type'], category=f['category'],
               quantity=qty, location=f['location'], description=f.get('description'), image=fname,
               pickup_date=f.get('pickup_date'), pickup_time=f.get('pickup_time'))
    db.session.add(r)
    db.session.commit()
    flash(f'Report submitted! Your Report ID is {r.report_id} (Status: Pending).', 'success')
    return redirect(url_for('dashboard'))


@app.route('/report/<int:rid>/update', methods=['POST'])
@need('collector', 'admin')
def update_report(rid):
    u, r = cur(), db.get_or_404(Report, rid)
    if u.role == 'collector' and r.collector_id != u.id: abort(403)
    st = request.form.get('status')
    allowed = STATUSES if u.role == 'admin' else COLLECTOR_STATUSES
    if st in allowed: r.status = st
    if request.form.get('notes'): r.notes = request.form['notes'][:500]
    cid = request.form.get('collector_id')
    if u.role == 'admin' and cid:
        r.collector_id = int(cid)
        if r.status == 'Pending': r.status = 'Assigned'
    db.session.commit()
    flash('Report updated.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/report/<int:rid>/delete', methods=['POST'])
@need('admin')
def delete_report(rid):
    db.session.delete(db.get_or_404(Report, rid))
    db.session.commit()
    flash('Report deleted.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/user/<int:uid>/toggle', methods=['POST'])
@need('admin')
def toggle_user(uid):
    t = db.get_or_404(User, uid)
    if t.id != cur().id: t.active = not t.active; db.session.commit()
    flash('User updated.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/user/add', methods=['POST'])
@need('admin')
def add_user():
    f = request.form
    if User.query.filter_by(email=f['email'].lower()).first() or f.get('role') not in ('citizen', 'collector', 'admin') or len(f.get('password', '')) < 8:
        flash('Could not add user (duplicate email, bad role or short password).', 'danger')
    else:
        db.session.add(User(full_name=f['full_name'], email=f['email'].lower(), phone=f.get('phone'), city=f.get('city'),
                            role=f['role'], password_hash=generate_password_hash(f['password'])))
        db.session.commit()
        flash('User added.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/api/reports')
@need()
def api_reports():
    u = cur()
    q = Report.query if u.role == 'admin' else Report.query.filter((Report.user_id == u.id) | (Report.collector_id == u.id))
    return jsonify([r.to_dict() for r in q.all()])


@app.route('/api/dashboard/stats')
@need('admin')
def api_stats():
    return jsonify(users=User.query.count(), reports=Report.query.count(),
                   by_status={x: Report.query.filter_by(status=x).count() for x in STATUSES})


@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(500)
def err(e):
    code = getattr(e, 'code', 500)
    msg = {403: 'You are not authorised to view this page.', 404: 'Page not found.', 500: 'Something went wrong on our side.'}[code]
    return render_template('error.html', code=code, msg=msg), code


def seed():
    if User.query.first(): return
    for n, e, p, r in [('Admin User', 'admin@cleancity.com', 'Admin@123', 'admin'), ('Ravi Collector', 'collector@cleancity.com', 'Collector@123', 'collector'),
                       ('Asha Citizen', 'citizen@cleancity.com', 'Citizen@123', 'citizen')]:
        db.session.add(User(full_name=n, email=e, phone='9999999999', address='Demo Street', city='Lucknow', role=r, password_hash=generate_password_hash(p)))
    db.session.commit()


if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    with app.app_context():
        db.create_all()
        seed()
    app.run(debug=True)
