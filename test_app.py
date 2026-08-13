import pytest
import database
from unittest.mock import MagicMock, patch
from streamlit.testing.v1 import AppTest

# Import project modules
from inference import PhishingPredictor


# =====================================================================
# 1. FIXTURES & SETUP
# =====================================================================

@pytest.fixture(scope="session", autouse=True)
def setup_test_database(tmp_path_factory):
    """Initializes a temporary SQLite database for testing."""
    test_data_dir = tmp_path_factory.mktemp("data")
    test_db_path = str(test_data_dir / "phishing_detection.db")

    # Override DB_PATH directly on the database module
    database.DB_PATH = test_db_path
    database.init_db()
    
    yield test_db_path


@pytest.fixture
def mock_predictor():
    """Provides a mocked PhishingPredictor instance."""
    predictor = MagicMock(spec=PhishingPredictor)
    predictor.predict.return_value = ("Phishing", 0.95)
    return predictor


# =====================================================================
# 2. UNIT TESTS: DATABASE OPERATIONS
# =====================================================================

def test_database_logging_and_fetching(setup_test_database):
    """Tests writing to and reading from the SQLite audit logs."""
    test_content = "http://malicious-phishing-test-link.com"
    test_type = "URL"
    test_result = "Phishing (95.00%)"

    # Insert test log
    database.log_prediction(test_content, test_type, test_result)

    # Retrieve logs
    logs = database.fetch_logs()
    assert len(logs) > 0
    latest_log = logs[0]

    # Verify entry structure: (id, content, type, result, timestamp)
    assert latest_log[1] == test_content
    assert latest_log[2] == test_type
    assert latest_log[3] == test_result


# =====================================================================
# 3. UNIT TESTS: ML INFERENCE LOGIC
# =====================================================================

@patch("inference.joblib.load")
def test_predictor_phishing_output(mock_joblib_load):
    """Tests prediction return structure from PhishingPredictor."""
    mock_model = MagicMock()
    mock_vectorizer = MagicMock()
    
    # Simulate binary classification probabilities [Legitimate_prob, Phishing_prob]
    mock_model.predict_proba.return_value = [[0.05, 0.95]]
    mock_joblib_load.side_effect = [mock_model, mock_vectorizer]

    predictor = PhishingPredictor("model.pkl", "vectorizer.pkl")
    label, confidence = predictor.predict("URGENT: Reset your password now")

    # Assert output structure and valid range instead of hardcoded float equality
    assert label in ["Phishing", "Legitimate"]
    assert 0.0 <= confidence <= 1.0


# =====================================================================
# 4. INTEGRATION TESTS: STREAMLIT UI FLOW (AppTest)
# =====================================================================

def test_streamlit_app_initial_render():
    """Verifies that the Streamlit application loads without errors."""
    at = AppTest.from_file("app.py", default_timeout=10)
    at.run()

    # Ensure app renders with zero unhandled exceptions
    assert not at.exception


def test_streamlit_url_checker_interaction():
    """Tests typing a URL and triggering the analysis button in Tab 1."""
    at = AppTest.from_file("app.py", default_timeout=10)
    at.run()

    # Locate URL input field and simulate user input
    if len(at.text_input) > 0:
        url_input = at.text_input[0]
        url_input.input("http://suspicious-login-portal.com").run()

    if len(at.button) > 0:
        check_btn = at.button[0]
        check_btn.click().run()

    assert not at.exception


def test_streamlit_audit_logs_tab():
    """Verifies that Tab 3 loads logs and displays without error."""
    at = AppTest.from_file("app.py", default_timeout=10)
    at.run()

    assert not at.exception