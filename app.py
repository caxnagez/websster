from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField, SelectMultipleField, SubmitField, IntegerField
from wtforms.validators import DataRequired, Length, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__, template_folder='templates')
print("DEBUG: Flask template folder:", app.template_folder)
app.config['SECRET_KEY'] = 'm7ByzOmWZJNUQ98FAsqiHnQgPCD_Cn2OKGW8BsoPi4Q'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///emergency_calls.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'

# Models

call_departments = db.Table('call_departments',
    db.Column('call_id', db.Integer, db.ForeignKey('call.id'), primary_key=True),
    db.Column('department_id', db.Integer, db.ForeignKey('department.id'), primary_key=True)
)

class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    calls = db.relationship('Call', secondary=call_departments, lazy='subquery',
                            backref=db.backref('departments', lazy=True))
    call_statuses = db.relationship('CallStatus', backref='department', lazy=True)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='user')
    calls_created = db.relationship('Call', foreign_keys='Call.creator_id', backref='creator', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Call(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    location = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    creation_date = db.Column(db.DateTime, default=datetime.utcnow)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    statuses = db.relationship('CallStatus', backref='call', lazy=True, cascade="all, delete-orphan")


class CallStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    call_id = db.Column(db.Integer, db.ForeignKey('call.id'), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=False)
    status = db.Column(db.String(20), default='open')
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('call_id', 'department_id', name='unique_call_department_status'),)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    role = SelectField('Role', choices=[('dispatcher', 'Dispatcher'), ('medical', 'Medical'), ('fire', 'Fire'), ('police', 'Police')], validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists.')

class CallForm(FlaskForm):
    location = StringField('Location', validators=[DataRequired(), Length(max=200)])
    description = TextAreaField('Description', validators=[DataRequired()])
    departments = SelectMultipleField('Departments', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Dispatch Call')

    def __init__(self, *args, **kwargs):
        super(CallForm, self).__init__(*args, **kwargs)
        self.departments.choices = [(d.id, d.name.title()) for d in Department.query.all()]


#Routes
@app.route('/')
def index():
    calls = []
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            calls = Call.query.order_by(Call.creation_date.desc()).all()
        elif current_user.role == 'dispatcher':
            calls = Call.query.order_by(Call.creation_date.desc()).all()
        elif current_user.role in ['medical', 'fire', 'police']:
            dept = Department.query.filter_by(name=current_user.role).first()
            if dept:
                 calls = Call.query.filter(Call.departments.contains(dept)).order_by(Call.creation_date.desc()).all()
        else:
            calls = []
    return render_template('index.html', calls=calls)

@app.route('/call/<int:id>')
@login_required
def call_detail(id):
    call = Call.query.get_or_404(id)
    if current_user.role == 'admin':
        pass
    elif current_user.role == 'dispatcher':
        pass
    elif current_user.role in ['medical', 'fire', 'police']:
        dept = Department.query.filter_by(name=current_user.role).first()
        if dept and dept not in call.departments:
             flash("You don't have permission to view this call.", "error")
             return redirect(url_for('index'))
    else:
        flash("Access denied.", "error")
        return redirect(url_for('index'))
    statuses_by_dept = {}
    for dept in call.departments:
        status_entry = CallStatus.query.filter_by(call_id=call.id, department_id=dept.id).first()
        if status_entry:
            statuses_by_dept[dept.name] = status_entry.status
        else:
            statuses_by_dept[dept.name] = 'open'

    return render_template('call_detail.html', call=call, statuses_by_dept=statuses_by_dept)

@app.route('/call/<int:id>/update_status', methods=['POST'])
@login_required
def update_call_status(id):
    call = Call.query.get_or_404(id)
    dept = Department.query.filter_by(name=current_user.role).first()
    if not dept or dept not in call.departments:
        flash("You don't have permission to update status for this call.", "error")
        return redirect(url_for('call_detail', id=call.id))

    new_status = request.form.get('status')
    if not new_status:
        flash("No status provided.", "error")
        return redirect(url_for('call_detail', id=call.id))

    valid_statuses = ['open', 'dispatched', 'on_way', 'arrived', 'closed']
    if new_status not in valid_statuses:
        flash(f"Invalid status: {new_status}", "error")
        return redirect(url_for('call_detail', id=call.id))

    status_entry = CallStatus.query.filter_by(call_id=call.id, department_id=dept.id).first()
    if status_entry:
        status_entry.status = new_status
    else:
        status_entry = CallStatus(call_id=call.id, department_id=dept.id, status=new_status)
        db.session.add(status_entry)

    db.session.commit()
    flash(f'Status for {dept.name.title()} updated to {new_status}.', 'success')
    return redirect(url_for('call_detail', id=call.id))

@app.route('/create_call', methods=['GET', 'POST'])
@login_required
def create_call():
    if current_user.role != 'dispatcher':
        flash("Only dispatchers can create calls.", "error")
        return redirect(url_for('index'))

    form = CallForm()
    if form.validate_on_submit():
        new_call = Call(
            location=form.location.data,
            description=form.description.data,
            creator_id=current_user.id,
        )
        db.session.add(new_call)
        selected_dept_ids = form.departments.data
        selected_depts = Department.query.filter(Department.id.in_(selected_dept_ids)).all()
        new_call.departments.extend(selected_depts)

        for dept in selected_depts:
            initial_status = CallStatus(call=new_call, department=dept, status='dispatched')
            db.session.add(initial_status)

        db.session.commit()
        dept_names = [d.name.title() for d in selected_depts]
        flash(f'Call dispatched to {", ".join(dept_names)}!', 'success')
        return redirect(url_for('index'))
    return render_template('create_call.html', form=form)

@app.route('/edit_call/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_call(id):
    call = Call.query.get_or_404(id)
    if current_user.role not in ['dispatcher', 'admin']:
        flash("You don't have permission to edit calls.", "error")
        return redirect(url_for('call_detail', id=call.id))

    form = CallForm(obj=call)
    if request.method == 'GET':
        form.departments.data = [d.id for d in call.departments]
    if form.validate_on_submit():
        call.location = form.location.data
        call.description = form.description.data
        call.departments.clear()
        selected_dept_ids = form.departments.data
        selected_depts = Department.query.filter(Department.id.in_(selected_dept_ids)).all()
        call.departments.extend(selected_depts)
        current_dept_ids = {d.id for d in selected_depts}
        statuses_to_delete = CallStatus.query.filter_by(call_id=call.id).filter(
            ~CallStatus.department_id.in_(current_dept_ids)
        ).all()
        for status_to_del in statuses_to_delete:
            db.session.delete(status_to_del)
        existing_dept_ids = {cs.department_id for cs in call.statuses}
        for dept in selected_depts:
            if dept.id not in existing_dept_ids:
                new_status = CallStatus(call_id=call.id, department_id=dept.id, status='dispatched')
                db.session.add(new_status)

        db.session.commit()
        flash('Call updated successfully!', 'success')
        return redirect(url_for('call_detail', id=call.id))

    return render_template('edit_call.html', form=form, call=call)

#Auth routes
from flask import Blueprint

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('auth/login.html', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, role=form.role.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('User registered successfully!')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)

app.register_blueprint(auth_bp)

#API
api_bp = Blueprint('api', __name__, url_prefix='/api')

@api_bp.route('/calls', methods=['GET'])
@login_required
def get_calls_api():
    calls_data = []
    if current_user.role == 'admin':
        calls = Call.query.order_by(Call.creation_date.desc()).all()
    elif current_user.role == 'dispatcher':
        calls = Call.query.order_by(Call.creation_date.desc()).all()
    elif current_user.role in ['medical', 'fire', 'police']:
        dept = Department.query.filter_by(name=current_user.role).first()
        if dept:
            calls = Call.query.filter(Call.departments.contains(dept)).order_by(Call.creation_date.desc()).all()
        else:
            calls = []
    else:
        return jsonify({'error': 'Permission denied'}), 403

    for c in calls:
        statuses_by_dept = {}
        for dept in c.departments:
            status_entry = CallStatus.query.filter_by(call_id=c.id, department_id=dept.id).first()
            if status_entry:
                statuses_by_dept[dept.name] = status_entry.status
            else:
                statuses_by_dept[dept.name] = 'open'

        calls_data.append({
            'id': c.id,
            'location': c.location,
            'description': c.description,
            'creation_date': c.creation_date.isoformat(),
            'creator': c.creator.username,
            'departments': [d.name for d in c.departments],
            'statuses_by_department': statuses_by_dept
        })
    return jsonify(calls_data)

@api_bp.route('/calls/<int:id>', methods=['GET'])
@login_required
def get_call_api(id):
    call = Call.query.get_or_404(id)
    if current_user.role == 'admin':
        pass
    elif current_user.role == 'dispatcher':
        pass
    elif current_user.role in ['medical', 'fire', 'police']:
        dept = Department.query.filter_by(name=current_user.role).first()
        if dept and dept not in call.departments:
            return jsonify({'error': 'Permission denied'}), 403
    else:
        return jsonify({'error': 'Permission denied'}), 403

    statuses_by_dept = {}
    for dept in call.departments:
        status_entry = CallStatus.query.filter_by(call_id=call.id, department_id=dept.id).first()
        if status_entry:
            statuses_by_dept[dept.name] = status_entry.status
        else:
            statuses_by_dept[dept.name] = 'open'

    call_data = {
        'id': call.id,
        'location': call.location,
        'description': call.description,
        'creation_date': call.creation_date.isoformat(),
        'creator': call.creator.username,
        'departments': [d.name for d in call.departments],
        'statuses_by_department': statuses_by_dept
    }
    return jsonify(call_data)

@api_bp.route('/calls/<int:id>/status', methods=['PUT'])
@login_required
def update_call_status_api(id):
    call = Call.query.get_or_404(id)
    dept = Department.query.filter_by(name=current_user.role).first()
    if not dept or dept not in call.departments:
        return jsonify({'error': 'Permission denied. You can only update status for your assigned department.'}), 403

    data = request.get_json() or {}
    new_status = data.get('status')

    if not new_status:
        return jsonify({'error': 'No status provided.'}), 400
    valid_statuses = ['open', 'dispatched', 'on_way', 'arrived', 'closed']
    if new_status not in valid_statuses:
        return jsonify({'error': f'Invalid status: {new_status}'}), 400

    status_entry = CallStatus.query.filter_by(call_id=call.id, department_id=dept.id).first()
    if status_entry:
        status_entry.status = new_status
    else:
        status_entry = CallStatus(call_id=call.id, department_id=dept.id, status=new_status)
        db.session.add(status_entry)

    db.session.commit()
    return jsonify({'message': f'Status for {dept.name} updated to {new_status}.', 'department': dept.name, 'status': new_status})

@api_bp.route('/calls', methods=['POST'])
@login_required
def create_call_api():
    if current_user.role != 'dispatcher':
        return jsonify({'error': 'Permission denied. Only dispatchers can create calls.'}), 403

    data = request.get_json() or {}
    required_fields = ['location', 'description', 'departments']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing field: {field}'}), 400

    if not isinstance(data['departments'], list):
        return jsonify({'error': 'Departments must be a list'}), 400

    dept_ids = data['departments']
    departments = Department.query.filter(Department.id.in_(dept_ids)).all()
    if len(departments) != len(dept_ids):
        return jsonify({'error': 'One or more department IDs are invalid'}), 400

    new_call = Call(
        location=data['location'],
        description=data['description'],
        creator_id=current_user.id,
    )
    db.session.add(new_call)
    new_call.departments.extend(departments)

    for dept in departments:
        initial_status = CallStatus(call=new_call, department=dept, status='dispatched')
        db.session.add(initial_status)
    db.session.commit()
    statuses_by_dept = {d.name: 'dispatched' for d in departments}

    return jsonify({'message': 'Call dispatched', 'id': new_call.id, 'departments': [d.name for d in departments], 'statuses_by_department': statuses_by_dept}), 201

@api_bp.route('/calls/<int:id>', methods=['PUT'])
@login_required
def update_call_api(id):
    call = Call.query.get_or_404(id)
    if current_user.role not in ['dispatcher', 'admin']:
        return jsonify({'error': 'Permission denied. Only dispatcher or admin can update calls.'}), 403

    data = request.get_json() or {}

    if 'location' in data:
        call.location = data['location']
    if 'description' in data:
        call.description = data['description']
    if 'departments' in data:
        if not isinstance(data['departments'], list):
            return jsonify({'error': 'Departments must be a list'}), 400
        dept_ids = data['departments']
        departments = Department.query.filter(Department.id.in_(dept_ids)).all()
        if len(departments) != len(dept_ids):
            return jsonify({'error': 'One or more department IDs are invalid'}), 400

        call.departments.clear()
        call.departments.extend(departments)

        current_dept_ids = {d.id for d in departments}
        statuses_to_delete = CallStatus.query.filter_by(call_id=call.id).filter(
            ~CallStatus.department_id.in_(current_dept_ids)
        ).all()
        for status_to_del in statuses_to_delete:
            db.session.delete(status_to_del)

        existing_dept_ids = {cs.department_id for cs in call.statuses}
        for dept in departments:
            if dept.id not in existing_dept_ids:
                new_status = CallStatus(call_id=call.id, department_id=dept.id, status='dispatched')
                db.session.add(new_status)

    db.session.commit()

    statuses_by_dept = {}
    for dept in call.departments:
        status_entry = CallStatus.query.filter_by(call_id=call.id, department_id=dept.id).first()
        if status_entry:
            statuses_by_dept[dept.name] = status_entry.status
        else:
            statuses_by_dept[dept.name] = 'open'

    return jsonify({'message': 'Call updated', 'departments': [d.name for d in call.departments], 'statuses_by_department': statuses_by_dept})

@api_bp.route('/calls/<int:id>', methods=['DELETE'])
@login_required
def delete_call_api(id):
    call = Call.query.get_or_404(id)
    if current_user.role != 'admin':
        return jsonify({'error': 'Permission denied. Only admins can delete calls.'}), 403

    db.session.delete(call)
    db.session.commit()
    return jsonify({'message': 'Call deleted'})

@app.route('/call/<int:id>/delete', methods=['POST'])
@login_required
def delete_call(id):
    if current_user.role != 'admin':
        flash("You don't have permission to delete calls.", "error")
        return redirect(url_for('call_detail', id=id))

    call = Call.query.get_or_404(id)
    db.session.delete(call)
    db.session.commit()
    flash(f'Call #{call.id} has been deleted.', 'success')
    return redirect(url_for('index'))

app.register_blueprint(api_bp)

def init_db_data():
    if __name__ != '__main__':
        return
    if not Department.query.first():
        med_dept = Department(name='medical')
        fire_dept = Department(name='fire')
        police_dept = Department(name='police')
        db.session.add_all([med_dept, fire_dept, police_dept])
        db.session.commit()
        
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', role='admin')
        admin_user.set_password('admin')
        db.session.add(admin_user)
        db.session.commit()
        
    if not User.query.filter_by(username='disp1').first():
        disp_user = User(username='disp1', role='dispatcher')
        disp_user.set_password('disp1')
        db.session.add(disp_user)
        db.session.commit()
        
    if not User.query.filter_by(username='medical').first():
        med_user = User(username='medical', role='medical')
        med_user.set_password('medical')
        db.session.add(med_user)
        db.session.commit()
        
    if not User.query.filter_by(username='fireman').first():
        ff_user = User(username='fireman', role='fire')
        ff_user.set_password('fireman')
        db.session.add(ff_user)
        db.session.commit()
        
    if not User.query.filter_by(username='police').first():
        po_user = User(username='police', role='police')
        po_user.set_password('police')
        db.session.add(po_user)
        db.session.commit()
        
    if not Call.query.first():
        dispatcher = User.query.filter_by(username='disp1').first()
        medical_dept = Department.query.filter_by(name='medical').first()
        fire_dept = Department.query.filter_by(name='fire').first()
        police_dept = Department.query.filter_by(name='police').first()
        
        call_police_only = Call(
            location="Test",
            description="police only",
            creator=dispatcher
        )
        call_police_only.departments.append(police_dept)
        db.session.add(call_police_only)
        initial_status_police = CallStatus(call=call_police_only, department=police_dept, status='dispatched')
        db.session.add(initial_status_police)

        call_medical_only = Call(
            location="Test",
            description="medical only",
            creator=dispatcher
        )
        call_medical_only.departments.append(medical_dept)
        db.session.add(call_medical_only)
        initial_status_medical = CallStatus(call=call_medical_only, department=medical_dept, status='dispatched')
        db.session.add(initial_status_medical)

        call_fire_only = Call(
            location="Test",
            description="firemans only",
            creator=dispatcher
        )
        call_fire_only.departments.append(fire_dept)
        db.session.add(call_fire_only)
        initial_status_fire = CallStatus(call=call_fire_only, department=fire_dept, status='dispatched')
        db.session.add(initial_status_fire)

        call_all = Call(
            location="Test",
            description="All departments",
            creator=dispatcher
        )
        call_all.departments.extend([medical_dept, fire_dept, police_dept])
        db.session.add(call_all)
        initial_status_med_all = CallStatus(call=call_all, department=medical_dept, status='dispatched')
        initial_status_fire_all = CallStatus(call=call_all, department=fire_dept, status='dispatched')
        initial_status_police_all = CallStatus(call=call_all, department=police_dept, status='dispatched')
        db.session.add_all([initial_status_med_all, initial_status_fire_all, initial_status_police_all])
        call_for_admin_delete = Call(
            location="Test",
            description="for admin deletion",
            creator=dispatcher
        )
        call_for_admin_delete.departments.extend([medical_dept, police_dept])
        db.session.add(call_for_admin_delete)
        initial_status_med_delete = CallStatus(call=call_for_admin_delete, department=medical_dept, status='open')
        initial_status_police_delete = CallStatus(call=call_for_admin_delete, department=police_dept, status='open')
        db.session.add_all([initial_status_med_delete, initial_status_police_delete])
        db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        init_db_data()
    app.run(debug=True)