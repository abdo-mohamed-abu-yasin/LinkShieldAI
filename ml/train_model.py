
import pandas as pd
import numpy as np
import re
import json
import ipaddress

from urllib.parse import urlparse
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

# =====================================
# 1. Load Dataset
# =====================================

DATASET_PATH = "ml/dataset.csv"

print("Loading dataset...")

df = pd.read_csv(DATASET_PATH)

print("Dataset shape:", df.shape)

# Keep only required columns
df = df[["URL", "label"]].dropna()

df["URL"] = df["URL"].astype(str)
df["label"] = df["label"].astype(int)

print("\nLabel distribution:")
print(df["label"].value_counts())

# =====================================
# 2. Feature Extraction
# =====================================

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "account",
    "secure",
    "update",
    "password",
    "bank",
    "signin",
    "confirm"
]

FEATURE_NAMES = [
    "urlLength",
    "domainLength",
    "dots",
    "hyphens",
    "hasHTTPS",
    "hasIP",
    "suspiciousKeywords",
    "subdomains"
]


def extract_features(input_url):

    try:
        url = urlparse(input_url)

        hostname = url.hostname or ""

        if not hostname:
            raise ValueError("Invalid hostname")

        full_url = input_url

        features = [
            len(full_url),

            len(hostname),

            full_url.count("."),

            full_url.count("-"),

            int(url.scheme.lower() == "https"),

            int(bool(re.fullmatch(
                r"(?:\d{1,3}\.){3}\d{1,3}",
                hostname
            ))),

            sum(
                keyword in full_url.lower()
                for keyword in SUSPICIOUS_KEYWORDS
            ),

            max(0, len(hostname.split(".")) - 2)
        ]

        return features

    except Exception:
        return None


print("\nExtracting URL features...")

X = []
y = []
groups = []

for url, label in zip(df["URL"], df["label"]):

    features = extract_features(url)

    if features is not None:
       X.append(features)
       y.append(label)
       groups.append(urlparse(url).hostname.lower())
X = np.array(X)
y = np.array(y)

print("Features shape:", X.shape)
print("Labels shape:", y.shape)


# =====================================
# 3. Split Dataset by Hostname
# =====================================

X = np.array(X)
y = np.array(y)
groups = np.array(groups)

cv = StratifiedGroupKFold(
    n_splits=5,
    shuffle=True,
    random_state=42
)

train_idx, test_idx = next(cv.split(X, y, groups))

X_train, X_test = X[train_idx], X[test_idx]
y_train, y_test = y[train_idx], y[test_idx]

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))

print(
    "Shared hostnames:",
    len(set(groups[train_idx]) & set(groups[test_idx]))
)

# =====================================
# 4. Train Random Forest
# =====================================

print("\nTraining Random Forest Model...")

model = RandomForestClassifier(
    n_estimators=100,
    max_depth=14,
    min_samples_leaf=2,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

print("Training completed!")

# =====================================
# 5. Model Evaluation
# =====================================

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("\n========== MODEL RESULTS ==========")

print("Accuracy:", round(accuracy * 100, 2), "%")

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        predictions,
        target_names=["Phishing", "Legitimate"]
    )
)

print("Confusion Matrix:")

print(confusion_matrix(y_test, predictions))

# =====================================
# 6. Feature Importance
# =====================================

print("\nFeature Importance:")

for name, importance in zip(
    FEATURE_NAMES,
    model.feature_importances_
):

    print(name, ":", round(importance, 4))

# =====================================
# 7. Export Model to JSON
# =====================================

def convert_tree(tree, node_id=0):

    feature = int(tree.feature[node_id])

    if feature == -2:

        counts = tree.value[node_id][0].tolist()

        total = sum(counts)

        probabilities = [
            float(value / total) if total else 0.0
            for value in counts
        ]

        return {
            "probabilities": probabilities
        }

    return {
        "feature": feature,
        "threshold": float(tree.threshold[node_id]),
        "left": convert_tree(
            tree,
            tree.children_left[node_id]
        ),
        "right": convert_tree(
            tree,
            tree.children_right[node_id]
        )
    }


print("\nExporting model...")

model_data = {
    "model_name": "LinkShield Random Forest",
    "feature_names": FEATURE_NAMES,
    "classes": model.classes_.tolist(),
    "trees": [
        convert_tree(estimator.tree_)
        for estimator in model.estimators_
    ]
}
with open("ml/model.json", "w") as file:

    json.dump(model_data, file)

print("\nModel exported successfully!")

print("Saved to: ml/model.json")

print("\n========== DONE ==========")
# =====================================
# 8. Test Known URLs
# =====================================

test_urls = [
    "https://www.google.com",
    "https://www.wikipedia.org",
    "https://www.github.com"
]

print("\n========== URL TESTING ==========")

for test_url in test_urls:

    features = extract_features(test_url)

    prediction = model.predict([features])[0]
    probabilities = model.predict_proba([features])[0]

    print("\nURL:", test_url)
    print("Prediction:", "Phishing" if prediction == 0 else "Legitimate")
    print("Probabilities:", dict(zip(model.classes_, probabilities)))