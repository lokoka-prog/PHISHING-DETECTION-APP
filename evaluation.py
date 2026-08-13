import sqlite3
import joblib
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, roc_curve, auc, RocCurveDisplay, ConfusionMatrixDisplay

def evaluate_model(db_path="phishing_detection.db", model_path="phishing_xgboost_model.pkl"):
    model = joblib.load(model_path)
    
    conn = sqlite3.connect(db_path)
    # Reading from the features table instead of features_table
    df = pd.read_sql_query("SELECT * FROM features", conn)
    conn.close()

    if df.empty:
        print("No records found in the 'features' table.")
        return None, None

    # Using classification as the ground truth target
    if 'classification' in df.columns:
        y_true = df['classification'].apply(lambda x: 1 if x == 'legitimate' else -1)
    else:
        y_true = pd.Series([1] * len(df))

    # Adjust these columns to match your exact feature set
    feature_cols = ['sender_domain_reputation', 'keyword_frequency', 'url_characteristics']
    X_new = df[feature_cols]

    y_pred_binary = model.predict(X_new)
    y_scores = model.predict_proba(X_new)[:, 1] if hasattr(model, "predict_proba") else y_pred_binary

    unique_classes = sorted(list(set(y_true).union(set(y_pred_binary))))
    label_map = {-1: 'Phishing', 1: 'Legitimate'}
    display_labels = [label_map.get(c, str(c)) for c in unique_classes]

    cm = confusion_matrix(y_true, y_pred_binary, labels=unique_classes)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=display_labels)
    
    fig_cm, ax_cm = plt.subplots(figsize=(6, 4))
    disp.plot(cmap=plt.cm.Blues, ax=ax_cm)
    ax_cm.set_title("Confusion Matrix")
    plt.tight_layout()
    plt.savefig("re_eval_confusion_matrix.png")
    plt.close()

    fig_roc, ax_roc = plt.subplots(figsize=(6, 4))
    try:
        fpr, tpr, _ = roc_curve(y_true, y_scores, pos_label=1)
        roc_auc = auc(fpr, tpr)
        roc_display = RocCurveDisplay(fpr=fpr, tpr=tpr, roc_auc=roc_auc, name='Phishing Detector')
        roc_display.plot(ax=ax_roc)
        ax_roc.set_title("ROC Curve")
        plt.tight_layout()
        plt.savefig("re_eval_roc_curve.png")
        plt.close()
    except Exception as e:
        print(f"ROC Curve Generation Skipped: {e}")
        fig_roc = None

    return fig_cm, fig_roc

if __name__ == "__main__":
    evaluate_model()