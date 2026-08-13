import os
from datetime import datetime
from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    text,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

# ---------------------------------------------------------
# Base Path Setup
# ---------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "phishing_detection.db")

Base = declarative_base()


# ---------------------------------------------------------
# Database Models
# ---------------------------------------------------------
class EmailRecord(Base):
    __tablename__ = "emails"
    id = Column(Integer, primary_key=True, index=True)
    sender = Column(String(255), nullable=False)
    subject = Column(String(255), nullable=False)
    body = Column(Text, nullable=False)
    received_at = Column(DateTime, default=datetime.utcnow, index=True)
    classification = Column(String(50), nullable=True)


class Feature(Base):
    __tablename__ = "features"
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"))
    sender_domain_reputation = Column(String(50), nullable=False)
    keyword_frequency = Column(Text, nullable=False)
    url_characteristics = Column(Text, nullable=False)
    email = relationship("EmailRecord")


class ManualCheck(Base):
    __tablename__ = "manual_checks"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), nullable=False, default="anonymous", index=True)
    input_text = Column(Text, nullable=False)
    check_type = Column(String(50), nullable=False)
    result = Column(String(50), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)


class ConnectedAccount(Base):
    __tablename__ = "connected_accounts"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), nullable=False, index=True)
    email_address = Column(String(255), nullable=False)
    added_at = Column(DateTime, default=datetime.utcnow)


class PerformanceMetric(Base):
    __tablename__ = "performance_metrics"
    id = Column(Integer, primary_key=True, index=True)
    model_name = Column(String(100), nullable=False)
    accuracy = Column(Float, nullable=False)
    precision = Column(Float, nullable=False)
    recall = Column(Float, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)


# ---------------------------------------------------------
# Engine & Session Setup
# ---------------------------------------------------------
engine = create_engine(
    f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False}
)
Session = sessionmaker(bind=engine)


# ---------------------------------------------------------
# Utility Helper Functions
# ---------------------------------------------------------
def init_db():
    """Creates all database tables and performs automatic schema migrations for existing tables."""
    Base.metadata.create_all(engine)

    # Self-healing migration for existing databases missing the username column
    with engine.connect() as conn:
        try:
            conn.execute(
                text(
                    "ALTER TABLE manual_checks ADD COLUMN username TEXT DEFAULT 'anonymous'"
                )
            )
            conn.commit()
        except Exception:
            # Column already exists or table was cleanly initialized
            pass


def log_prediction(username, input_text, check_type, result):
    """Logs prediction results linked to a specific username."""
    session = Session()
    try:
        user_str = username or "anonymous"
        check = ManualCheck(
            username=user_str,
            input_text=input_text,
            check_type=check_type,
            result=result,
        )
        session.add(check)
        session.commit()
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def fetch_logs(username):
    """Fetches logged predictions exclusively for the active username as dictionary objects."""
    session = Session()
    try:
        if not username:
            return []

        logs = (
            session.query(ManualCheck)
            .filter(ManualCheck.username == username)
            .order_by(ManualCheck.timestamp.desc())
            .all()
        )

        return [
            {
                "id": l.id,
                "input_text": l.input_text,
                "check_type": l.check_type,
                "result": l.result,
                "timestamp": l.timestamp,
            }
            for l in logs
        ]
    finally:
        session.close()


def add_connected_account(username, email_address):
    """Links a new email account address to a user."""
    session = Session()
    try:
        account = ConnectedAccount(
            username=username, email_address=email_address
        )
        session.add(account)
        session.commit()
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def fetch_connected_accounts(username):
    """Retrieves all linked email accounts for a specific user."""
    session = Session()
    try:
        if not username:
            return []
        accounts = (
            session.query(ConnectedAccount)
            .filter(ConnectedAccount.username == username)
            .all()
        )
        return [acc.email_address for acc in accounts]
    finally:
        session.close()


if __name__ == "__main__":
    init_db()
    print("Database and all tables initialized successfully.")
