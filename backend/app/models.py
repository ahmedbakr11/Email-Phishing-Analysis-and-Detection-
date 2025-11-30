from .extensions import db


##table for user's data
class User(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    fullname = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(), nullable=False)
    role = db.Column(db.String(5), nullable=False, default="user")
    failed_login_attempts = db.Column(db.Integer, nullable=False, default=0)
    suspended = db.Column(db.Boolean, nullable=False, default=False)

    # Suspended mechanism functions
    def record_failed_login(self):
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 3:
            self.suspended = True
        db.session.commit()

    def reset_login_state(self):
        self.failed_login_attempts = 0
        self.suspended = False
        db.session.commit()

    ##prints the added username in terminal
    def __repr__(self):
        return f" <User {self.username}>"

    ##funtions for CRUD operations
    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def update(
        self,
        fullname_data,
        username_data,
        email_data,
        password_data,
        role_data,
        suspended_data,
    ):
        self.fullname = fullname_data
        self.username = username_data
        self.email = email_data
        self.password = password_data
        self.role = role_data
        self.suspended = suspended_data
        db.session.commit()
