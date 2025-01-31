from flask_wtf import FlaskForm
from flask import Flask, render_template, redirect, url_for, flash
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email as EmailValidator, EqualTo, Length
import os
from functools import wraps
from flask import abort
from flask_login import current_user
from wtforms.validators import Email, Optional


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
DATABASE_URL = os.environ.get(
    'DATABASE_URL',
    'postgresql://postgres:+-++@localhost:5432/postgres'
)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = False

db = SQLAlchemy(app)
engine = create_engine(DATABASE_URL)
Base = declarative_base()
Session = sessionmaker(bind=engine)

class Account(UserMixin, db.Model):
    __tablename__ = 'account'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), default='student')
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'), nullable=True)  # Добавляем связь с группами
    group = db.relationship('Group', backref='students', lazy=True)  # Отношение между группами и студентами


    def __init__(self, username, email, password, role='student', group_id=None):
        self.username = username
        self.email = email
        self.role = role
        self.set_password(password)
        self.group_id = group_id

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)



class UserForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    role = SelectField('Роль', choices=[('admin', 'Администратор'), ('student', 'Ученик'), ('teacher', 'Преподаватель')], validators=[DataRequired()])
    group_id = SelectField('Группа', coerce=int)
    password = PasswordField('Новый пароль', validators=[Optional(), Length(min=6)])
    confirm_password = PasswordField('Подтверждение нового пароля', validators=[Optional(), EqualTo('password')])
    submit = SubmitField('Сохранить изменения')


class Group(db.Model):
    __tablename__ = 'groups'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=True)

    # Отношение к расписанию
    schedules = db.relationship('Schedule', backref='group', lazy=True)



class Schedule(db.Model):
    __tablename__ = 'schedules'

    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    time = db.Column(db.DateTime, nullable=False)



# Форма регистрации
class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(min=3, max=20)])
    email = StringField('Email', validators=[DataRequired(), EmailValidator()])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Подтвердите пароль', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Зарегистрироваться')


# Форма входа
class LoginForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')


class GroupForm(FlaskForm):
    name = StringField('Название группы', validators=[DataRequired()])
    description = StringField('Описание группы', validators=[DataRequired()])
    submit = SubmitField('Создать группу')


class StudentForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField('Email', validators=[DataRequired(), EmailValidator()])
    group_id = SelectField('Группа', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Сохранить')


# Настройка LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def role_required(role):
    def wrapper(func):
        @wraps(func)
        def decorated_view(*args, **kwargs):
            if current_user.role != role:
                abort(403)
            return func(*args, **kwargs)
        return decorated_view
    return wrapper


@login_manager.user_loader
def load_user(user_id):
    return Account.query.get(int(user_id))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            # Создаем нового пользователя
            new_account = Account(
                username=form.username.data,
                email=form.email.data,
                password=form.password.data,
            )
            db.session.add(new_account)
            db.session.commit()
            flash('Регистрация прошла успешно!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка регистрации: {e}', 'error')
            return render_template('register.html', form=form)
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Account.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Вы успешно вошли!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неправильное имя пользователя или пароль.', 'error')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы.', 'success')
    return redirect(url_for('login'))


@app.route('/', methods=["GET", "POST"])
@login_required
def index():
    return render_template('index.html')





@app.route('/schedule', methods=['GET'])
@login_required
@role_required('admin')  # доступ только администраторам
def view_schedule():
    schedule = Schedule.query.all()  # Замените Schedule на вашу модель расписания
    return render_template('view_schedule.html', schedule=schedule)

#админ
@app.route('/admin')
@login_required
@role_required('admin')
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/admin/users')
@login_required
@role_required('admin')
def manage_users():
    users = Account.query.all()
    return render_template('manage_users.html', users=users)


@app.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def create_user():
    form = UserForm()  # Форма для создания пользователей
    if form.validate_on_submit():
        new_user = Account(
            username=form.username.data,
            email=form.email.data,
            password=form.password.data,
            role=form.role.data
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Пользователь создан.', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('create_user.html', form=form)


@app.route('/admin/delete_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')  # Только для администраторов
def delete_user(user_id):
    user = Account.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('Пользователь удалён!', 'success')
    return redirect(url_for('manage_users'))


@app.route('/admin/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')  # Только для администраторов
def edit_user(user_id):
    user = Account.query.get_or_404(user_id)
    form = UserForm(obj=user)
    form.group_id.choices = [(g.id, g.name) for g in Group.query.all()]

    if form.validate_on_submit():
        # Обновляем поля
        user.username = form.username.data
        user.email = form.email.data
        user.role = form.role.data
        user.group_id = form.group_id.data
        # Если пользователь указал новый пароль, обновляем его
        if form.password.data:
            user.password_hash = generate_password_hash(form.password.data)



        db.session.commit()
        flash('Данные пользователя обновлены!', 'success')
        return redirect(url_for('manage_users'))  # Перенаправление на страницу управления пользователями

    return render_template('edit_user.html', form=form, user=user)



@app.route('/admin/students/<int:student_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_student(student_id):
    student = Account.query.get_or_404(student_id)
    groups = Group.query.all()
    form = StudentForm(obj=student)
    form.group_id.choices = [(g.id, g.name) for g in groups]

    if form.validate_on_submit():
        student.username = form.username.data
        student.email = form.email.data
        student.group_id = form.group_id.data
        db.session.commit()
        flash('Данные студента обновлены.', 'success')
        return redirect(url_for('group_students', group_id=student.group_id))
    return render_template('edit_student.html', form=form, student=student)



@app.route('/admin/students/<int:student_id>/delete', methods=['POST'])
@login_required
@role_required('admin')
def delete_student(student_id):
    student = Account.query.get_or_404(student_id)
    db.session.delete(student)
    db.session.commit()
    flash('Студент удален.', 'success')
    return redirect(url_for('group_students', group_id=student.group_id))


# Для создания и управления группами (GET и POST)
@app.route('/admin/groups', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_groups():
    groups = Group.query.all()
    form = GroupForm()

    if form.validate_on_submit():
        try:
            new_group = Group(
                name=form.name.data,
                description=form.description.data
            )
            db.session.add(new_group)
            db.session.commit()
            flash('Группа успешно создана.', 'success')
            return redirect(url_for('manage_groups'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при создании группы: {e}', 'error')
    else:
        if form.errors:
            flash(f'Ошибка валидации формы: {form.errors}', 'error')

    return render_template('groups.html', groups=groups, form=form)



@app.route('/admin/groups/edit/<int:group_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_group(group_id):
    group = Group.query.get_or_404(group_id)
    form = GroupForm(obj=group)

    if form.validate_on_submit():
        group.name = form.name.data
        group.description = form.description.data
        db.session.commit()
        flash('Группа успешно обновлена.', 'success')
        return redirect(url_for('manage_groups'))

    return render_template('edit_group.html', form=form, group=group)



@app.route('/admin/groups/delete/<int:group_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_group(group_id):
    group = Group.query.get_or_404(group_id)
    try:
        # Удаление студентов из группы
        Account.query.filter_by(group_id=group_id).update({'group_id': None})
        db.session.commit()

        db.session.delete(group)
        db.session.commit()
        flash('Группа успешно удалена.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при удалении группы: {e}', 'error')
    return redirect(url_for('manage_groups'))



@app.route('/admin/groups/<int:group_id>/students', methods=['GET'])
@login_required
@role_required('admin')
def group_students(group_id):
    group = Group.query.get_or_404(group_id)
    students = Account.query.filter_by(group_id=group_id, role='student').all()
    return render_template('group_students.html', group=group, students=students)




#админ все

#преподаватели
@app.route('/teacher/schedule/add', methods=['GET', 'POST'])
@login_required
@role_required('teacher')
def teacher_add_schedule():
    form = ScheduleForm()
    form.group.choices = [(g.id, g.name) for g in current_user.groups]
    if form.validate_on_submit():
        new_schedule = Schedule(
            title=form.title.data,
            description=form.description.data,
            date=form.date.data,
            start_time=form.start_time.data,
            end_time=form.end_time.data,
            group_id=form.group.data,
            teacher_id=current_user.id
        )
        db.session.add(new_schedule)
        db.session.commit()
        flash('Занятие добавлено.', 'success')
        return redirect(url_for('teacher_schedule'))
    return render_template('add_schedule.html', form=form)
#преподаватели все

#студенты
@app.route('/student/schedule', methods=['GET'])
@login_required
@role_required('student')
def student_schedule():
    schedules = Schedule.query.filter(Schedule.group_id.in_([g.id for g in current_user.groups])).all()
    return render_template('student_schedule.html', schedules=schedules)


#студенты все



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(debug=True)
