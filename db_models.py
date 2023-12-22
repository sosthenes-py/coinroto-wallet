from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()


class Member(UserMixin, db.Model):
    __tablename__ = "members"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False)
    email2 = db.Column(db.String(250), default='')
    email_status = db.Column(db.Boolean, default=False)
    twofa_secret = db.Column(db.String(250))
    twofa_status = db.Column(db.Boolean, default=False)
    session_id = db.Column(db.String(250))
    password = db.Column(db.String(250), nullable=False)
    code = db.Column(db.String(250))
    logins = db.Column(db.String)
    pin = db.Column(db.String)
    reg_date = db.Column(db.String(250))
    otp = db.Column(db.String(250))
    otp_time = db.Column(db.String(250))

    wallets = db.relationship("Wallet", back_populates="user", uselist=False, cascade="all, delete-orphan")
    history = db.relationship("ProgramHistory", backref="user", cascade="all, delete-orphan")
    watch_list = db.relationship("WatchList", backref="user", cascade="all, delete-orphan")
    addresses = db.relationship("Address", backref="user", cascade="all, delete-orphan")
    sessions = db.relationship("Session", backref="user", cascade="all, delete-orphan")
    auto_payouts = db.relationship("AutoPayout", backref="user", cascade="all, delete-orphan")
    auto_exchanges = db.relationship("AutoExchange", backref="user", cascade="all, delete-orphan")


class Wallet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.Integer, db.ForeignKey('members.id', name="wallet_members_fk"), nullable=False)
    btc = db.Column(db.Float(50), default=0)
    eth = db.Column(db.Float(50), default=0)
    ltc = db.Column(db.Float(50), default=0)
    bch = db.Column(db.Float(50), default=0)
    etc = db.Column(db.Float(50), default=0)
    zec = db.Column(db.Float(50), default=0)
    bnb = db.Column(db.Float(50), default=0)
    xrp = db.Column(db.Float(50), default=0)
    eos = db.Column(db.Float(50), default=0)
    ada = db.Column(db.Float(50), default=0)
    trx = db.Column(db.Float(50), default=0)
    doge = db.Column(db.Float(50), default=0)
    sol = db.Column(db.Float(50), default=0)
    usdttrc = db.Column(db.Float(50), default=0)
    usdctrc = db.Column(db.Float(50), default=0)
    xmr = db.Column(db.Float(50), default=0)
    dash = db.Column(db.Float(50), default=0)
    busd = db.Column(db.Float(50), default=0)

    user = db.relationship("Member", back_populates="wallets")


class ProgramHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.Integer, db.ForeignKey('members.id', name="program_history_member_fk"), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    amt = db.Column(db.Float, nullable=False, default=0)
    method = db.Column(db.String(250), nullable=False)
    time = db.Column(db.String(250), nullable=False)
    wallet = db.Column(db.String(250))
    status = db.Column(db.Integer, default=0)
    hash = db.Column(db.String(250))
    label = db.Column(db.String(250))
    price = db.Column(db.String(250))
    qty = db.Column(db.Float, default=0)
    detail = db.Column(db.String(250))
    fee = db.Column(db.Float, default=0)
    tx_id = db.Column(db.String)


class WatchList(db.Model):
    __tablename__ = "watch_list"
    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.Integer, db.ForeignKey('members.id', name="watch_list_member_fk"), nullable=False)
    token = db.Column(db.String(250), nullable=False)
    time = db.Column(db.String(250), nullable=False)


class Address(db.Model):
    __tablename__ = "address"
    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.Integer, db.ForeignKey('members.id', name="address_member_fk"), nullable=False)
    token = db.Column(db.String(250), nullable=False)
    wallet = db.Column(db.String(250), nullable=False)
    label = db.Column(db.String(250))
    time = db.Column(db.String(250), nullable=False)


class Session(db.Model):
    __tablename__ = "sessions"
    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.Integer, db.ForeignKey('members.id', name="sessions_member_fk"), nullable=False)
    token = db.Column(db.String(250), nullable=False)
    ip = db.Column(db.String(250), nullable=False)
    device = db.Column(db.String(250), default='')
    time = db.Column(db.String(250), nullable=False)


class AutoPayout(db.Model):
    __tablename__ = "auto_payout"
    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.Integer, db.ForeignKey('members.id', name="auto_payout_member_fk"), nullable=False)
    token = db.Column(db.String(250), nullable=False)
    min = db.Column(db.Float(250), nullable=False)
    rest = db.Column(db.Float(250), default=0)
    wallet = db.Column(db.String(250), nullable=False)
    time = db.Column(db.String(250), nullable=False)


class AutoExchange(db.Model):
    __tablename__ = "auto_exchange"
    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.Integer, db.ForeignKey('members.id', name="auto_exchange_member_fk"), nullable=False)
    from_token = db.Column(db.String(250), nullable=False)
    to_token = db.Column(db.String(250), nullable=False)
    min = db.Column(db.Float(250), nullable=False)
    time = db.Column(db.String(250), nullable=False)


class MinMax(db.Model):
    __tablename__ = "min_max"
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(250), nullable=False)
    min = db.Column(db.Float(250), nullable=False)
    max = db.Column(db.Float(250), nullable=False)
