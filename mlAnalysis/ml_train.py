import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

CSV_FILE = "packet_log.csv"
MODEL_FILE = "decision_tree_model.pkl"

# -----------------------------
# Load CSV
# -----------------------------
df = pd.read_csv(CSV_FILE)

# -----------------------------
# Feature selection
# -----------------------------
# Keep only numeric fields or encode categorical
features = [
    "protocol",
    "src_port",
    "dst_port",
    "packet_len",
    "tcp_flags",
    "is_private_dst",
    "is_multicast_dst",
    "src_asn"
]

# Encode src_country as numeric
country_map = {code: idx for idx, code in enumerate(df["src_country"].unique())}
df["src_country_num"] = df["src_country"].map(country_map)
features.append("src_country_num")

# Optional: encode protocol_name if needed
protocol_name_map = {name: idx for idx, name in enumerate(df["protocol_name"].unique())}
df["protocol_name_num"] = df["protocol_name"].map(protocol_name_map)
features.append("protocol_name_num")
# anything non-zero is malicious
df["ml_label"] = (df["suspicious"] != 0).astype(int)

X = df[features]
y = df["ml_label"]  # 0=normal,1=malicious
print(df["ml_label"].value_counts())

# -----------------------------
# Train/test split
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# -----------------------------
# Train Decision Tree
# -----------------------------
clf = DecisionTreeClassifier(max_depth=8, random_state=42)
clf.fit(X_train, y_train)

# -----------------------------
# Evaluate
# -----------------------------
y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))

# -----------------------------
# Save model
# -----------------------------
joblib.dump(clf, "decision_tree_model.pkl")


print(f"Model saved to {MODEL_FILE}")
print(df["suspicious"].value_counts())
