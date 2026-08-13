from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

Base = declarative_base()

class EmailRecord(Base):
    __tablename__ = 'emails'
    id = Column(Integer, primary_key=True, index=True)
    sender = Column(String(255), nullable=False)
    subject = Column(String(255), nullable=False)
    body = Column(Text, nullable=False)
    received_at = Column(DateTime, default=datetime.utcnow, index=True)
    classification = Column(String(50), nullable=True)

class Feature(Base):
    __tablename__ = 'features'
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey('emails.id'))
    sender_domain_reputation = Column(String(50), nullable=False)
    keyword_frequency = Column(Text, nullable=False)
    url_characteristics = Column(Text, nullable=False)
    email = relationship("EmailRecord")

class ManualCheck(Base):
    __tablename__ = 'manual_checks'
    id = Column(Integer, primary_key=True, index=True)
    input_text = Column(Text, nullable=False)
    check_type = Column(String(50), nullable=False)
    result = Column(String(50), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

class PerformanceMetric(Base):
    __tablename__ = 'performance_metrics'
    id = Column(Integer, primary_key=True, index=True)
    model_name = Column(String(100), nullable=False)
    accuracy = Column(Float, nullable=False)
    precision = Column(Float, nullable=False)
    recall = Column(Float, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

engine = create_engine('sqlite:///phishing_detection.db')
Session = sessionmaker(bind=engine)

def init_db():
    """Creates all four tables in the database."""
    Base.metadata.create_all(engine)

def log_prediction(input_text, check_type, result):
    """Logs prediction results into the manual_checks table."""
    session = Session()
    try:
        check = ManualCheck(input_text=input_text, check_type=check_type, result=result)
        session.add(check)
        session.commit()
    finally:
        session.close()

def fetch_logs():
    """Fetches all logged prediction records."""
    session = Session()
    try:
        logs = session.query(ManualCheck).all()
        return [(l.id, l.input_text, l.check_type, l.result, l.timestamp) for l in logs]
    finally:
        session.close()

if __name__ == "__main__":
    init_db()
    print("Database and all 4 tables initialized successfully.")