#!/usr/bin/env python3
"""
train_baseline.py
Train a simple RandomForest on prepared features. This assumes you created a labels.csv matching session start times.
labels.csv should have columns: start,label  where start matches the 'start' field in features.
"""
import argparse
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
import joblib
import os

parser = argparse.ArgumentParser()
parser.add_argument('--features', required=True)
parser.add_argument('--labels', required=True)
parser.add_argument('--out', default='models/rf_baseline.joblib')
args = parser.parse_args()

X = pd.read_parquet(args.features)
y = pd.read_csv(args.labels)

# merge on start time; be careful about formatting
merged = pd.merge(X, y, on='start', how='inner')
if merged.empty:
    raise SystemExit("Merged dataset is empty. Check labels and features 'start' values.")

label = merged['label']
# select numeric features only (drop non-numeric)
features = merged.select_dtypes(include=[float, int]).drop(columns=['duration'], errors='ignore')

# fill na
features = features.fillna(0)

X_train, X_test, y_train, y_test = train_test_split(features, label, test_size=0.3, random_state=42, stratify=label)

clf = RandomForestClassifier(n_estimators=200, class_weight='balanced', random_state=42)
print("[*] training RandomForest on {} samples".format(len(X_train)))
clf.fit(X_train, y_train)

pred = clf.predict(X_test)
probs = clf.predict_proba(X_test)[:, 1] if hasattr(clf, "predict_proba") else None

print(classification_report(y_test, pred))
if probs is not None:
    try:
        print("ROC-AUC:", roc_auc_score(y_test, probs))
    except Exception:
        pass

os.makedirs(os.path.dirname(args.out), exist_ok=True)
joblib.dump(clf, args.out)
print('wrote model to', args.out)
