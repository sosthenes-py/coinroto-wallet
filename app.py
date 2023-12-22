import random
from functools import wraps

import pyotp as pyotp
import qrcode as qrcode
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, abort
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter

import api
from db_models import db, Member, Wallet, WatchList, ProgramHistory, Address, Session, AutoPayout, AutoExchange, MinMax
from forms import LoginForm, RegisterForm, TwoFaForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
import datetime as dt
import re
from api import all_coins, fees
from decimal import Decimal
import uuid
from email_sender import EmailSender


SITE_NAME = "COINROTO"
app = Flask(__name__)
app.config['SECRET_KEY'] = "gfdcvbkjiuhygtfdcgvhjk541564bvgcvbjhg"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydb.db'
limiter = Limiter(key_func=lambda: request.remote_addr, app=app, storage_uri="memory://", headers_enabled=True)

db.init_app(app)
login_manager = LoginManager(app)
Migrate(app=app, db=db)
CSRFProtect(app)


with app.app_context():
    db.create_all()

login_manager.login_view = "login"
login_manager.login_message = "You are out of session. Please login again"


def sql_to_dict(obj, exempt=None):
    our_dict = {}
    for col in obj.__table__.columns:
        if exempt:
            if col.name not in exempt:
                our_dict[col.name] = getattr(obj, col.name)
    return our_dict


@app.context_processor
def inject_globals():
    return dict(my_round=my_round, format_date=format_date, session=session)


def my_round(value):
    if '.' in str(value):
        after_dec = str(value).split('.')[1]
        count = len(after_dec)
        if count >= 4:
            return int(value * (10 ** 4)) / (10 ** 4)
        return value
    return value


def get_token_price():
    return sql_to_dict(db.session.query(Wallet).filter_by(id=1).first(), exempt=['id', 'member_id'])


def format_date(timestamp, fmt='', option_limit: int = None):
    if timestamp == 0:
        return 'NULL'
    if option_limit:
        if dt.datetime.now().timestamp() - int(timestamp) < option_limit:
            return f'{st(timestamp)} ago'
    return f"{dt.datetime.fromtimestamp(int(timestamp)):{fmt}}"


def st(timestamp):
    timestamp = abs(int(dt.datetime.now().timestamp()) - int(timestamp))
    if timestamp == 0:
        return "moments"
    days = int(timestamp / (60 * 60 * 24))
    hrs = int(timestamp % (60 * 60 * 24) / (60 * 60))
    mins = int(timestamp % (60 * 60) / 60)
    secs = (timestamp % (60 * 60)) % 60
    time_str = ''
    if days > 0:
        days_str = 'day'
        if days > 1:
            days_str = "days"
        return f'{days} {days_str}'
    elif hrs > 0:
        hrs_str = 'hr'
        if hrs > 1:
            hrs_str = 'hrs'
        return f'{hrs} {hrs_str}'
    elif mins > 0:
        mins_str = 'min'
        if mins > 1:
            mins_str = 'mins'
        return f'{mins} {mins_str}'
    elif secs > 0:
        secs_str = 'sec'
        if secs > 1:
            secs_str = 'secs'
        return f'moments'


def get_timestamp():
    return int(dt.datetime.now().timestamp())


def is_strong_password(password):
    if len(password) < 8:
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    if not any(char.isdigit() for char in password):
        return False
    special_characters = re.compile(r'[!@#$%^&*(),.?":{}|<>]')
    if not special_characters.search(password):
        return False
    return True


def valid_otp(code):
    totp = pyotp.TOTP(current_user.twofa_secret)
    if not totp.verify(code):
        return False
    return True


def session_validate(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if session.get('session_id', 'None') not in [sess.token for sess in current_user.sessions]:
            flash('Session has ended. Login again', 'error')
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return wrapper


@login_manager.user_loader
def load_user(user):
    return db.session.query(Member).filter_by(id=user).first()


@app.route('/', methods=['POST', 'GET'])
def login():  # put application's code here
    form = LoginForm()
    if request.method == "GET":
        return render_template('auth/login.html', form=form)
    # csrf_token = request.headers.get('X-CSRFToken')
    if form.validate_on_submit():
        result = db.session.query(Member).filter_by(email=form.email.data).first()
        if result:
            if check_password_hash(result.password, form.password.data):
                login_user(result)
                session_id = str(uuid.uuid4())
                session['session_id'] = session_id
                time = get_timestamp()
                if result.logins is None:
                    result.logins = f'{time}={time}'
                else:
                    time1, time2 = result.logins.split("=")
                    result.logins = f'{time1}={time}'

                # SESSION
                user_agent, ip = request.user_agent.string, request.remote_addr
                if user_agent in [sess.device for sess in result.sessions]:
                    db.session.query(Session).filter(Session.member_id == result.id, Session.device == user_agent).update({"ip": ip, "token": session_id})
                else:
                    new_session = Session(member_id=result.id, token=session_id, time=time, ip=ip, device=user_agent)
                    db.session.add(new_session)

                db.session.commit()
                next_ = request.args.get('next')
                return redirect(next_ or url_for('user_dashboard'))
            flash('Invalid login credentials', 'danger')
        else:
            flash('Invalid login credentials', 'danger')
    return render_template('auth/login.html', form=form)


@app.route('/user/logout', methods=['GET'])
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    if request.method == 'GET':
        code = request.args.get('code', None)
        result = db.session.query(Member).filter_by(code=code).first()
        if result and code:
            return render_template('auth/verify-email.html', email=result.email)
        return abort(404)
    email = request.form['email']
    pass_ = request.form['pass']
    result = db.session.query(Member).filter_by(email=email).first()
    if result:
        if check_password_hash(result.password, pass_):
            result.email_status = True
            result.email = result.email2
            result.code = ''
            db.session.commit()
            return jsonify({'status': 'success', 'msg': 'Email verification successful'})
        return jsonify({'status': 'error', 'msg': 'Incorrect password'})
    return jsonify({'status': 'error', 'msg': 'An error occurred. Please refresh this page'})


@app.route('/auth/register', methods=['POST', 'GET'])
def register():  # put application's code here
    form = RegisterForm()
    if form.validate_on_submit():
        if form.password.data == form.conf_password.data:
            if is_strong_password(form.password.data):
                if not db.session.query(Member).filter_by(email=form.email.data).first():
                    code = ''
                    for _ in range(10):
                        code += f'{random.randint(0, 9)}'

                    new_user = Member(email=form.email.data, password=generate_password_hash(form.password.data), code=code, email2=form.email.data)
                    db.session.add(new_user)
                    db.session.commit()
                    new_wallet = Wallet(member_id=new_user.id)
                    db.session.add(new_wallet)
                    new_wl1 = WatchList(member_id=new_user.id, token='ltc', time=get_timestamp())
                    new_wl2 = WatchList(member_id=new_user.id, token='doge', time=get_timestamp())
                    new_wl3 = WatchList(member_id=new_user.id, token='trx', time=get_timestamp())
                    new_wl4 = WatchList(member_id=new_user.id, token='btc', time=get_timestamp())
                    new_wl5 = WatchList(member_id=new_user.id, token='eth', time=get_timestamp())
                    new_wl6 = WatchList(member_id=new_user.id, token='usdttrc', time=get_timestamp())
                    db.session.bulk_save_objects([new_wl1, new_wl2, new_wl3, new_wl4, new_wl5, new_wl6])

                    # SESSION
                    session_id = str(uuid.uuid4())
                    session['session_id'] = session_id
                    new_session = Session(member_id=new_user.id, token=session_id, time=get_timestamp(), ip=request.remote_addr, device=request.user_agent.string)
                    db.session.add(new_session)

                    # TWOFA
                    new_user.twofa_secret = pyotp.random_base32()
                    uri = pyotp.totp.TOTP(new_user.twofa_secret).provisioning_uri(
                        name=new_user.email,
                        issuer_name=SITE_NAME)
                    qr_path = f'static/img/twofa/{new_user.email}.png'
                    qrcode.make(uri).save(qr_path)

                    time = get_timestamp()
                    new_user.logins = f'{time}={time}'
                    db.session.commit()
                    login_user(new_user)
                    EmailSender('registration', code=code, email=form.email.data).send_email()
                    return redirect(url_for('setup_twofa'))
                flash("Email already exists", "danger")
            flash("Password must contain up to 8 characters: 1 capital letter, 1 small letter, 1 number and 1 special character", "danger")
        flash("Passwords do not match!", "danger")
        return render_template('auth/register.html', form=form)
    return render_template('auth/register.html', form=form)


@app.route('/setup-twofa', methods=['POST', 'GET'])
@login_required
@session_validate
def setup_twofa():
    form = TwoFaForm()
    if form.validate_on_submit():
        if valid_otp(form.code.data):
            current_user.twofa_status = True
            flash('2FA Setup Completed. Please wait...', 'success')
            return render_template('auth/twofa.html', form=form, secret=current_user.twofa_secret, message="success")
        flash('Incorrect Code', 'danger')
        return render_template('auth/twofa.html', form=form, secret=current_user.twofa_secret, message="null")
    return render_template('auth/twofa.html', form=form, secret=current_user.twofa_secret, message="null")


@app.route('/auth/forgot-password', methods=['POST', 'GET'])
def forgot_password():
    return render_template('auth/forgot-password.html')


@app.route('/user/dashboard', methods=['POST', 'GET'])
@login_required
@session_validate
def user_dashboard():
    token_price = get_token_price()
    user_wallets = sql_to_dict(current_user.wallets, exempt=['id', 'member_id'])
    if request.method == "GET":
        all_wallets = {}
        for token, price in token_price.items():
            all_wallets[token] = {'name': all_coins[token], 'price': price, 'balance': user_wallets[token]}
        return render_template('user/dashboard.html', wallet=all_wallets, page="dashboard")

    # IF POST, SETUP DASHBOARD
    # SET UP THE WATCH LIST
    wl_html = ''
    for wl in current_user.watch_list[-3:]:
        perc = calculate_perc_incr(wl.token)
        perc_class = "success"
        perc_sign = "+"
        if perc < 0:
            perc_sign = "-"
            perc_class = "danger"
        wl_html += f"""
            <div class="col-md col-sm-6">
                <div class="card border-primary-hover">
                    <div class="card-body p-4">
                        <div class="d-flex align-items-center gap-2">
                            <img src="{url_for('static', filename=f'img/tokens/{wl.token}.png')}" class="w-rem-5 flex-none" alt="..."> 
                            <a href="{url_for('user_wallet', token=wl.token)}" class="h6 stretched-link">{wl.token.upper()}</a>
                        </div>
                    <div class="text-sm fw-semibold mt-3">{my_round(user_wallets[wl.token])} {wl.token.upper()}</div>
                    <div class="d-flex align-items-center gap-2 mt-1 text-xs"><span class="badge badge-xs bg-{perc_class}"><i class="bi bi-arrow-up-right"></i> </span><span>{perc_sign}{abs(perc):.1f}%</span></div>
                </div>
            </div>
        </div>
            """

    wl_html += """
        <div class="col-md-1 d-none d-md-block">
            <div class="card h-md-100 d-flex flex-column align-items-center justify-content-center py-4 bg-body-secondary bg-opacity-75 bg-opacity-100-hover"><a href="#addWLModal" class="stretched-link text-body-secondary" data-bs-toggle="modal"><i class="bi bi-plus-lg"></i></a>
        </div>
        """

    wl_html2 = ''
    for wl in reversed(current_user.watch_list):
        wl_html2 += f"""
                <div class="flex-none">
                    <div class="rounded-3 p-3 p-sm-4 bg-body-secondary">
                        <div class="d-flex align-items-center gap-2">
                            <img src="{url_for('static', filename=f'img/tokens/{wl.token}.png')}" class="w-rem-5" alt="...">
                            <h6 class="text-sm fw-semibold">{my_round(user_wallets[wl.token])} {wl.token.upper()}</h6>
                        </div>
                        <div class="mt-4 fw-bold text-heading">${user_wallets[wl.token]*token_price[wl.token]:,.2f}</div>
                    </div>
                </div>
                """

    # SET UP TOTAL BALANCE
    total_balance = 0
    total_perc = 0
    for token, balance in sql_to_dict(current_user.wallets, exempt=['id', 'member_id']).items():
        balance_usd = float(balance)*float(token_price[token])
        total_balance += balance_usd
        total_perc += calculate_perc_incr(token)

    # INCOME & EXPENSES
    total_income = 0
    total_expense = 0
    for history in current_user.history:
        if history.name == "deposit" and history.status == 1 and not history.detail:
            total_income += history.amt
        if history.name == "withdraw" and history.status == 1 and not history.detail:
            total_expense += history.amt

    # PLOT GRAPH
    x_data = [dt.datetime.fromtimestamp(int(history.time)).strftime("%Y-%m-%d %H:%M") for history in current_user.history if history.name == "deposit" and not history.detail]
    y_data = [history.amt for history in current_user.history if history.name == "deposit" and not history.detail]

    # TRANSACTION HISTORY
    tx_history = ""
    id_ = 0
    for history in reversed(current_user.history):
        if history.name in ['deposit', 'withdraw'] and id_ < 7 and not history.detail:
            display_time = format_date(timestamp=history.time, fmt='%d %b %H:%M', option_limit=172800)
            if history.name == "deposit":
                name_class = "success"
                name = "Deposit"
                sign = "+"
            else:
                name_class = "danger"
                name = "Withdrawal"
                sign = "-"

            if history.status == 1:
                status_name = "Completed"
                status_class = "success"
            elif history.status == 0:
                status_name = "Pending"
                status_class = "warning"
            else:
                status_name = "Failed"
                status_class = "danger"

            tx_history += f"""
            <div class="list-group-item d-flex align-items-center justify-content-between gap-6">
                <div class="d-flex align-items-center gap-3">
                    <div class="icon icon-shape rounded-circle icon-sm flex-none w-rem-10 h-rem-10 text-sm bg-{name_class} bg-opacity-25 text-{name_class}"><i class="bi bi-send-fill"></i></div>
                        <div class=""><span class="d-block text-heading text-sm fw-semibold">{all_coins[history.method].title()} {name}</span><span class="d-none d-sm-block text-muted text-xs">{display_time}</span></div>
                    </div>
                    <div class="d-none d-md-block text-sm">{history.wallet[:int((3/4)*len(history.wallet))]}...{history.wallet[-4:]}</div>
                    <div class="d-none d-md-block"><span class="badge bg-body-secondary text-{status_class}">{status_name}</span></div>
                    <div class="text-end"><span class="d-block text-heading text-sm fw-bold">{sign}{my_round(history.qty):,} {history.method.upper()} </span><span class="d-block text-muted text-xs">{history.amt:,.2f} USD</span></div>
                </div>

            """
            id_ += 1

    if tx_history == "":
        tx_history = """
            <div class="list-group-item d-flex align-items-center justify-content-between gap-6">
                <div class="d-flex align-items-center gap-3">
                    <div class="d-none d-md-block text-sm">Nothing here yet...</div>
                </div>
            </div>
        """

    # FEES DISCOUNT
    user_wallet_deposit_totals = {tk: 0 for tk, bal in user_wallets.items()}
    for history in current_user.history:
        if history.name == "deposit" and not history.detail:
            user_wallet_deposit_totals[history.method] = user_wallet_deposit_totals[history.method] + history.amt
    wallet_list_sorted = dict(sorted(user_wallet_deposit_totals.items(), key=lambda item: item[1], reverse=True))
    fees_discount = ""
    for tk, bal in wallet_list_sorted.items():
        fees_discount += f"""
        <div class="d-flex bg-body-secondary gap-3 rounded-3 p-4">
            <div class="w-rem-8 h-rem-8 flex-none"><img src="{url_for('static', filename='img/tokens/{}.png'.format(tk))}" alt="..."></div>
                <div class="vstack gap-2">
                    <div class="d-flex mb-1">
                        <div class=""><span class="d-block text-heading text-sm fw-semibold">{all_coins[tk]}</span> <span class="d-block text-muted text-xs">{bal:,.2f} USD</span></div>
                            <div class="ms-auto d-block text-heading text-sm fw-semibold">{my_round(bal/token_price[tk])} {tk.upper()}</div>
                        </div>
                        <div class="progress bg-body-tertiary">
                            <div class="progress-bar bg-primary" role="progressbar" aria-label="Basic example" style="width:{(bal/50000)*100}%" aria-valuenow="{(bal/50000)*100}" aria-valuemin="0" aria-valuemax="100"></div>
                        </div>
                    </div>
                </div>
        """

    return jsonify({'wl_block': wl_html, 'wl_block2': wl_html2, 'status': 'success', 'total_balance': total_balance, 'total_income': total_income, 'total_expense': total_expense, 'total_perc': total_perc, 'graph': {'x_data': x_data, 'y_data': y_data}, "tx_history": tx_history, "fees_discount": fees_discount})


def calculate_perc_incr(token, name="deposit"):
    today = dt.datetime.now()
    prev_week_start = today - dt.timedelta(days=today.weekday()+7)
    prev_week_end = prev_week_start + dt.timedelta(days=7)
    this_week_start = today - dt.timedelta(days=today.weekday())

    prev_week_income = 0
    this_week_income = 0
    for history in current_user.history:
        history_time = dt.datetime.fromtimestamp(int(history.time))
        if prev_week_start <= history_time <= prev_week_end:
            if history.method == token and history.name == name and history.status == 1:
                prev_week_income += history.amt
        if this_week_start <= history_time <= today:
            if history.method == token and history.name == name and history.status == 1:
                this_week_income += history.amt

    if prev_week_income == 0 and this_week_income == 0:
        perc = 0
    elif prev_week_income == 0:
        perc = 100
    else:
        perc = ((this_week_income/prev_week_income)*100) - 100
    return perc


@app.route('/user/wallet/<token>', methods=['POST', 'GET', 'PUT'])
@login_required
@session_validate
def user_wallet(token):
    token_price = get_token_price()
    user_wallets = sql_to_dict(current_user.wallets, exempt=['id', 'member_id'])
    if request.method == "GET":
        all_wallets = {}
        for tk, price in token_price.items():
            all_wallets[tk] = {'name': all_coins[tk], 'price': price, 'balance': user_wallets[tk], 'fee': fees[tk]}
        return render_template('user/wallet.html', wallet=all_wallets, page="wallet", token=token)

    elif request.method == "POST":
        status = "success"
        # FOR POST

        # TODAY & ALL STATS
        today_in_qty, today_in_usd, today_out_qty, today_out_usd = 0, 0, 0, 0
        all_in_qty, all_in_usd, all_out_qty, all_out_usd = 0, 0, 0, 0
        all_inflows, all_outflows = "", ""

        # TODAY & ALL STATS && TRANSACTION HISTORY
        for history in reversed(current_user.history):
            if history.status == 1 and history.method == token and not history.detail:
                if history.name == "deposit" and dt.datetime.fromtimestamp(int(history.time)).date() == dt.datetime.now().date():
                    today_in_qty += history.qty
                    today_in_usd += history.amt
                elif history.name == "deposit":
                    all_in_qty += history.qty
                    all_in_usd += history.amt

                if history.name == "withdraw" and dt.datetime.fromtimestamp(int(history.time)).date() == dt.datetime.now().date():
                    today_out_qty += history.qty
                    today_out_usd += history.amt
                elif history.name == "withdraw":
                    all_out_qty += history.qty
                    all_out_usd += history.amt

            # TRANSACTION HISTORY
            if history.name == "deposit" and history.method == token:
                if history.status == 1:
                    status_name = "Completed"
                    status_class = "success"
                else:
                    status_name = "Failed"
                    status_class = "danger"
                tx_id = f'#{history.tx_id}'
                short_name = 'IN'
                if history.detail:
                    tx_id = f'{history.detail}#{history.tx_id}'
                    short_name = 'CV'
                all_inflows += f"""
                <div class="mb-4 inflows_card" data-tx_id="{history.tx_id}" data-wallet="{history.wallet}" data-qty="{my_round(history.qty)}">
                    <div class="d-flex align-items-center gap-3">
                        <div class="icon icon-shape flex-none text-base text-bg-success rounded-circle">{short_name}</div>
                            <div>
                                <h6 class="progress-text mb-1 d-block">{tx_id}</h6>
                                <p class="text-muted text-xs"><span class="fw-bold text-{status_class}">{status_name}</span> - {format_date(history.time, '%d %b %Y', 86400)}</p>
                            </div>
                            <div class="text-end ms-auto"><span class="h6 text-sm">+{float(my_round(history.qty)):,} {history.method.upper()}</span></div>
                        </div>
                    </div>
                """

            if history.name == "withdraw" and history.method == token:
                if history.status == 1:
                    status_name = "Completed"
                    status_class = "success"
                elif history.status == 0:
                    status_name = "Pending"
                    status_class = "warning"
                else:
                    status_name = "Failed"
                    status_class = "danger"
                tx_id = f'#{history.tx_id}'
                short_name = 'OUT'
                if history.detail:
                    tx_id = f'{history.detail}#{history.tx_id}'
                    short_name = 'CVT'
                all_outflows += f"""
                <div class="mb-4 outflows_card" data-tx_id="{history.tx_id}" data-wallet="{history.wallet}" data-qty="{my_round(history.qty)}">
                    <div class="d-flex align-items-center gap-3">
                        <div class="icon icon-shape flex-none text-base text-bg-danger rounded-circle">{short_name}</div>
                            <div>
                                <h6 class="progress-text mb-1 d-block">{tx_id}</h6>
                                <p class="text-muted text-xs"><span class="fw-bold text-{status_class}">{status_name}</span> - {format_date(history.time, '%d %b %Y', 86400)}</p>
                            </div>
                            <div class="text-end ms-auto"><span class="h6 text-sm">-{float(my_round(history.qty)):,} {history.method.upper()}</span></div>
                        </div>
                    </div>
                """

        if today_in_qty == 0:
            today_in_qty = '0.000'
        if today_out_qty == 0:
            today_out_qty = '0.000'
        if all_out_qty == 0:
            all_out_qty = '0.000'
        if all_in_qty == 0:
            all_in_qty = '0.000'

        in_perc = calculate_perc_incr(token)
        in_perc_class = "success"
        in_perc_sign = "+"
        if in_perc < 0:
            in_perc_sign = "-"
            in_perc_class = "danger"

        out_perc = calculate_perc_incr(token)
        out_perc_class = "success"
        out_perc_sign = "+"
        if out_perc < 0:
            out_perc_sign = "-"
            out_perc_class = "danger"

        # CHART
        in_x_data = [dt.datetime.fromtimestamp(int(history.time)).strftime("%Y-%m-%d")
                     for history in current_user.history if history.name == "deposit"
                     and history.method == token
                     and not history.detail]
        in_y_data = [history.amt for history in current_user.history
                     if history.name == "deposit"
                     and history.method == token
                     and not history.detail]

        out_x_data = [dt.datetime.fromtimestamp(int(history.time)).strftime("%Y-%m-%d")
                      for history in current_user.history if history.name == "withdraw"
                      and history.method == token
                      and not history.detail]
        out_y_data = [history.amt for history in current_user.history
                      if history.name == "withdraw"
                      and history.method == token
                      and not history.detail]

        # GET ADDRESSES
        all_addr = ""
        all_addr_count = 0
        for addr in reversed(current_user.addresses):
            if all_addr_count <= 20 and addr.token == token:
                all_addr_count += 1
                user_history_wallets = [history.time for history in reversed(current_user.history)
                                        if history.name == "deposit" and history.wallet == addr.wallet]
                if user_history_wallets:
                    last_used = format_date(user_history_wallets[0], "%d %b, %Y", 86400*5)
                else:
                    last_used = 'Never'
                all_addr += f"""
                <div class="position-relative d-flex align-items-center p-3 rounded-3 bg-body-secondary-hover addr_card" 
                data-wallet="{addr.wallet}" 
                data-label="{addr.label}" 
                data-time="{format_date(addr.time, '%d %b, %Y', 86400)}" 
                data-last_used="{last_used}" 
                data-wallet2="{addr.wallet[:int((2/5)*len(addr.wallet))]}...{addr.wallet[-4:]}">
                    <div class="flex-none">
                        <img src="{ url_for('static', filename='img/tokens/{}.png'.format(addr.token)) }" width="30em" class="w-rem-50 w-md-0 rounded" alt="...">
                    </div>
                    <div class="ms-3 ms-md-4 flex-fill">
                        <div class="stretched-link text-limit text-sm text-heading fw-semibold" role="button" data-bs-toggle="offcanvas" data-bs-target="#cardDetailsOffcanvas" aria-controls="cardDetailsOffcanvas">{addr.wallet}</div>
                        </div>
                        <div class="d-none d-sm-block ms-auto text-end">
                            <span class="badge bg-body-secondary text-primary">{addr.label}</span>
                            <div class="d-none d-sm-block text-xs text-muted mt-2">Last used: {last_used}</div>
                        </div>
                    </div>
                """

        # GET ADDRESS INFLOW
        addr_inflows = ""
        wallet = request.form.get('wallet')
        for history in current_user.history:
            if history.name == "deposit" and history.wallet == wallet:
                if history.status == 1:
                    status_name = "Completed"
                    status_class = "success"
                else:
                    status_name = "Failed"
                    status_class = "danger"
                addr_inflows += f"""
                                    <div class="mb-4 inflows_card" data-tx_id="{history.tx_id}" data-wallet="{history.wallet}" data-qty="{my_round(history.qty)}">
                                        <div class="d-flex align-items-center gap-3">
                                            <div class="icon icon-shape flex-none text-base text-bg-success rounded-circle">IN</div>
                                                <div>
                                                    <h6 class="progress-text mb-1 d-block">#{history.tx_id}</h6>
                                                    <p class="text-muted text-xs"><span class="fw-bold text-{status_class}">{status_name}</span> - {format_date(history.time, '%d %b %H:%M', 86400)}</p>
                                                </div>
                                                <div class="text-end ms-auto"><span class="h6 text-sm">+{float(my_round(history.qty)):,} {history.method.upper()}</span></div>
                                            </div>
                                        </div>
                                    """
        if addr_inflows == "":
            status = "warning"

        return jsonify({'status': 'success',
                        "stat": {
                            "in": {
                                "perc": f'{in_perc_sign}{abs(in_perc)}',
                                "class": in_perc_class,
                                "today_qty": my_round(today_in_qty),
                                "today_usd": f'{today_in_usd:,.2f}',
                                "all_qty": my_round(all_in_qty),
                                "all_usd": f'{all_in_usd:,.2f}'
                            },
                            "out": {
                                "perc": f'{out_perc_sign}{abs(out_perc)}',
                                "class": out_perc_class,
                                "today_qty": my_round(today_out_qty),
                                "today_usd": f'{today_out_usd:,.2f}',
                                "all_qty": my_round(all_out_qty),
                                "all_usd": f'{all_out_usd:,.2f}'
                            }
                        },
                        "chart": {
                            "in": {
                                "x_data": in_x_data,
                                "y_data": in_y_data
                            },
                            "out": {
                                "x_data": out_x_data,
                                "y_data": out_y_data
                            }
                        },
                        "history": {
                            "in": all_inflows,
                            "out": all_outflows
                        },
                        "all_addr": all_addr,
                        "addr_inflows": {
                            "status": status,
                            "inflows": addr_inflows
                        }

                        })

    elif request.method == "PUT":
        if not current_user.email_status:
            return jsonify({'status': 'error', 'msg': 'Please verify your email first'})

        if request.form['action'] == "convert":
            from_token = token
            to_token = request.form['to_token']
            from_amt = Decimal(request.form['from_amt'])
            from_price = Decimal(token_price[from_token])
            to_price = Decimal(token_price[to_token])
            from_bal = Decimal(user_wallets[from_token])
            to_bal = Decimal(user_wallets[to_token])

            rate = from_price/to_price
            to_amt = rate*from_amt
            if from_amt > from_bal:
                return jsonify({'status': 'error', 'msg': 'Insufficient balance'})
            from_bal -= from_amt
            to_bal += to_amt
            db.session.query(Wallet).filter_by(member_id=current_user.id).update({from_token: from_bal, to_token: to_bal})

            from_tx_id = ''
            to_tx_id = ''
            for _ in range(7):
                rand_no = random.randint(0, 9)
                from_tx_id += f'{rand_no}'
                to_tx_id += f'{rand_no+1}'
            to_history = ProgramHistory(
                member_id=current_user.id,
                detail='convert',
                name='deposit',
                amt=float(to_amt * to_price),
                qty=float(to_amt),
                method=to_token,
                time=get_timestamp(),
                price=float(to_price),
                status=1,
                tx_id=to_tx_id
            )
            from_history = ProgramHistory(
                member_id=current_user.id,
                detail='convert',
                name='withdraw',
                amt=float(from_amt * from_price),
                qty=float(from_amt),
                method=from_token,
                time=get_timestamp(),
                price=float(from_price),
                status=1,
                tx_id=from_tx_id
            )
            db.session.bulk_save_objects([to_history, from_history])
            db.session.commit()

            # REFRESH WALLET DATA
            return jsonify({'status': 'success', 'msg': 'Conversion successful'})

        elif request.form['action'] == 'withdraw':
            qty = Decimal(request.form['qty'])
            addr = request.form['addr']
            code = request.form['code']
            fee = Decimal(fees[token]['send']) + Decimal(0.4/100)*qty
            price = Decimal(token_price[token])
            total_qty = qty + fee
            bal = Decimal(user_wallets[token])

            # VALIDATIONS
            if not valid_otp(code):
                return jsonify({'status': 'error', 'msg': f'Invalid code'})
            if not api.is_address_valid(token, addr):
                return jsonify({'status': 'error', 'msg': f'Invalid address for {all_coins[token]}'})
            if total_qty > bal:
                return jsonify({'status': 'error', 'msg': 'Insufficient balance'})

            # MAKE WITHDRAWAL
            withdrawal = api.make_withdrawal(token, float(qty), addr)
            if withdrawal and withdrawal.status == "pending" or withdrawal.status == "completed":
                bal -= total_qty
                db.session.query(Wallet).filter_by(member_id=current_user.id).update({token: bal})

                tx_id = ''
                for _ in range(7):
                    tx_id += f'{random.randint(0, 9)}'
                new_history = ProgramHistory(
                    member_id=current_user.id,
                    name='withdraw',
                    amt=float(qty * price),
                    qty=float(qty),
                    method=token,
                    time=get_timestamp(),
                    price=float(price),
                    status=0,
                    tx_id=withdrawal.id,
                    wallet=addr,
                    fee=fee
                )
                db.session.add(new_history)
                db.session.commit()
                return jsonify({'status': 'success', 'msg': 'Withdrawal processing'})
            else:
                return jsonify({'status': 'error', 'msg': 'An error occurred'})

        elif request.form['action'] == "create_address":
            address = api.generate_wallet(token, current_user.id)
            new_addr = Address(
                member_id=current_user.id,
                token=token,
                wallet=address,
                time=get_timestamp()
            )
            db.session.add(new_addr)
            db.session.commit()
            min_deposit = api.get_token_info(token, 'min_receive')
            return jsonify({'status': 'success', 'msg': 'Action success', 'min_deposit': min_deposit, 'addr': address})


@app.route('/user/add-to-wl', methods=['POST'])
@login_required
@session_validate
def add_to_wl():
    token = request.form['token']
    wl_tokens = {wl: wl.token for wl in current_user.watch_list}
    for obj, tk in wl_tokens.items():
        if tk == token:
            current_user.watch_list.remove(obj)
    if token not in wl_tokens.values():
        del current_user.watch_list[0]
    new_wl = WatchList(token=token, member_id=current_user.id, time=get_timestamp())
    db.session.add(new_wl)
    db.session.commit()

    user_wallets = sql_to_dict(current_user.wallets, exempt=['id', 'member_id'])
    wl_html = ''
    for wl in current_user.watch_list[-3:]:
        perc = calculate_perc_incr(wl.token)
        perc_class = "success"
        perc_sign = "+"
        if perc < 0:
            perc_sign = "-"
            perc_class = "danger"
        wl_html += f"""
            <div class="col-md col-sm-6">
                <div class="card border-primary-hover">
                    <div class="card-body p-4">
                        <div class="d-flex align-items-center gap-2">
                            <img src="{url_for('static', filename=f'img/tokens/{wl.token}.png')}" class="w-rem-5 flex-none" alt="..."> 
                            <a href="{url_for('user_wallet', token=wl.token)}" class="h6 stretched-link">{wl.token.upper()}</a>
                        </div>
                    <div class="text-sm fw-semibold mt-3">{my_round(user_wallets[wl.token])} {wl.token.upper()}</div>
                    <div class="d-flex align-items-center gap-2 mt-1 text-xs"><span class="badge badge-xs bg-{perc_class}"><i class="bi bi-arrow-up-right"></i> </span><span>{perc_sign}{abs(perc):.1f}%</span></div>
                </div>
            </div>
        </div>
            """

    wl_html += """
    <div class="col-md-1 d-none d-md-block">
        <div class="card h-md-100 d-flex flex-column align-items-center justify-content-center py-4 bg-body-secondary bg-opacity-75 bg-opacity-100-hover"><a href="#addWLModal" class="stretched-link text-body-secondary" data-bs-toggle="modal"><i class="bi bi-plus-lg"></i></a>
    </div>
    """
    return jsonify({'status': 'success', 'msg': f'{token.upper()} has been added to watch list', 'content': wl_html})


@app.route('/settings/general', methods=['GET', 'POST'])
@login_required
@session_validate
def settings_general():
    token_price = get_token_price()
    user_wallets = sql_to_dict(current_user.wallets, exempt=['id', 'member_id'])
    if request.method == "GET":
        all_wallets = {}
        for tk, price in token_price.items():
            all_wallets[tk] = {'name': all_coins[tk], 'price': price, 'balance': user_wallets[tk], 'fee': fees[tk]}
        return render_template('user/settings/general.html', wallet=all_wallets, page="settings")
    elif request.method == "POST":
        if request.form['action'] == "email-change":
            if db.session.query(Member).filter_by(email=request.form['email']).first():
                return jsonify({'status': 'error', 'msg': 'Email error. Please take a different email'})

            code = ''
            for _ in range(10):
                code += f'{random.randint(0, 9)}'
            current_user.code = code
            current_user.email2 = request.form['email']
            db.session.commit()
            EmailSender('action', code=code, email=current_user.email).send_email()
            return jsonify({'status': 'success', 'msg': 'Success. Now check your inbox for further instructions'})


@app.route('/settings/sessions', methods=['GET', 'POST'])
@login_required
@session_validate
def settings_sessions():
    token_price = get_token_price()
    user_wallets = sql_to_dict(current_user.wallets, exempt=['id', 'member_id'])
    if request.method == "GET":
        all_wallets = {}
        for tk, price in token_price.items():
            all_wallets[tk] = {'name': all_coins[tk], 'price': price, 'balance': user_wallets[tk], 'fee': fees[tk]}
        return render_template('user/settings/sessions.html', wallet=all_wallets, page="settings")
    elif request.method == 'POST':
        id_ = request.form['id']
        if id_ == '0':
            for sess in current_user.sessions:
                if sess.token != session.get('session_id'):
                    db.session.delete(sess)
            db.session.commit()
            return jsonify({'status': 'success', 'msg': 'Sessions terminated successfully'})

        result = db.session.query(Session).filter(Session.member_id == current_user.id, Session.id == id_).first()
        if result:
            db.session.delete(result)
            db.session.commit()
            return jsonify({'status': 'success', 'msg': 'Session terminated successfully'})
        return jsonify({'status': 'error', 'msg': 'Session does not exist'})


@app.route('/settings/auto-payout', methods=['GET', 'POST'])
@login_required
@session_validate
def settings_auto_payout():
    token_price = get_token_price()
    user_wallets = sql_to_dict(current_user.wallets, exempt=['id', 'member_id'])
    if request.method == "GET":
        all_wallets = {}
        for tk, price in token_price.items():
            all_wallets[tk] = {'name': all_coins[tk], 'price': price, 'balance': user_wallets[tk], 'fee': fees[tk]}

        minmax = {}
        for tk, _ in user_wallets.items():
            res = db.session.query(MinMax).filter_by(token=tk).first()
            minmax[tk] = {'min': res.min, 'max': res.max}

        return render_template('user/settings/auto-payout.html', wallet=all_wallets, page="settings", minmax=minmax)

    elif request.method == 'POST':
        action = request.form['action']
        if action == "retrieve":
            body = ""
            for payout in reversed(current_user.auto_payouts):
                body += f"""
                <tr>
                  <td>
                     <div class="d-flex align-items-center gap-3 ps-1">
                        <div><span class="d-block text-heading fw-bold">{all_coins[payout.token]}</span></div>
                     </div>
                  </td>
                  <td >{my_round(payout.min)} {payout.token.upper()}</td>
                  <td >{my_round(payout.rest)} {payout.token.upper()}</td>
                  <td>{payout.wallet[:int((3/4)*len(payout.wallet))]}...{payout.wallet[-4:]}</td>
                   <td>{format_date(payout.time, '%d %b, %Y', 86400)}</td>
                  <td><button type="button" class="btn btn-sm btn-square btn-danger w-rem-6 h-rem-6 trash" data-id="{payout.id}"><i class="bi bi-trash"></i></button></td>
               </tr>
                """
            return jsonify({'status': 'success', 'msg': 'success', 'body': body})

        elif action == "add":
            token = request.form['token']
            min_ = float(request.form['min'])
            rest = float(request.form['rest'])
            wallet = request.form['wallet']
            code = request.form.get('code', '')

            if rest > min_:
                return jsonify({'status': 'error', 'msg': f'Rest balance cannot be greater than minimum balance'})

            # VALIDATE TOKEN RECEIVED
            if token not in user_wallets.keys():
                raise 'Invalid token'

            # VALIDATE OTP
            if not valid_otp(code):
                return jsonify({'status': 'error', 'msg': f'Invalid OTP'})

            # VALIDATE ADDRESS
            if not api.is_address_valid(token, wallet):
                return jsonify({'status': 'error', 'msg': f'Invalid address for {all_coins[token]}'})

            # CHECK IF METHOD ALREADY EXISTS
            if db.session.query(AutoPayout).filter(AutoPayout.member_id == current_user.id, AutoPayout.token == token).first():
                return jsonify({'status': 'error', 'msg': f'Payout method for {token.upper()} already exists'})

            # CHECK MIN AND MAX
            minmax = db.session.query(MinMax).filter_by(token=token).first()
            if min_ > minmax.max or min_ < minmax.min:
                return jsonify({'status': 'error',
                                'msg': f'Limits are from {minmax.min}{token.upper()} - {minmax.max}{token.upper()}'})

            new_payout = AutoPayout(
                member_id=current_user.id,
                token=token,
                min=min_,
                rest=rest,
                wallet=wallet,
                time=get_timestamp()
            )
            db.session.add(new_payout)
            db.session.commit()

            return jsonify({'status': 'success', 'msg': 'Method added successfully'})

        elif action == "trash":
            id_ = request.form['id']
            result = db.session.query(AutoPayout).filter(AutoPayout.member_id == current_user.id, AutoPayout.id == id_).first()
            if result:
                db.session.delete(result)
                db.session.commit()
                return jsonify({'status': 'success', 'msg': f'Method deleted successfully'})
            return jsonify({'status': 'error', 'msg': f'Method does not exist'})


@app.route('/settings/auto-exchange', methods=['GET', 'POST'])
@login_required
@session_validate
def settings_auto_exchange():
    token_price = get_token_price()
    user_wallets = sql_to_dict(current_user.wallets, exempt=['id', 'member_id'])
    if request.method == "GET":
        all_wallets = {}
        for tk, price in token_price.items():
            all_wallets[tk] = {'name': all_coins[tk], 'price': price, 'balance': user_wallets[tk], 'fee': fees[tk]}
        return render_template('user/settings/sessions.html', wallet=all_wallets, page="settings")
    elif request.method == 'POST':
        pass
        return jsonify({'status': 'error', 'msg': 'Session does not exist'})


if __name__ == '__main__':
    app.run()
