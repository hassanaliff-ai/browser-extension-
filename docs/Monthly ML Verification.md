# Monthly machine-learning verification

Verified on 4 October 2026: **10 focused tests passed** and **63 existing
reporting and dashboard checks passed**. Tests used temporary SQLite databases,
synthetic labelled activity and mocked LLM/SMTP responses. No real report was
emailed and no live LLM request was made.

1. Empty history reports insufficient data.
2. Constant history does not produce a misleading model assessment.
3. Target-month and future observations never enter training.
4. A fixed seed reproduces model results.
5. A synthetic large activity spike is flagged for administrator review.
6. Outputs exclude browsing targets and device identifiers.
7. LLM prompts, saved report evidence and simulated delivery preserve one snapshot;
   repeated preparation/delivery do not generate or send duplicates.
8. ML access rejects unauthenticated, password-only and ingestion credentials;
   completed two-factor sessions are accepted.
9. Incomplete months and invalid dates are rejected.
10. Monthly reports renders the ML action and explains insufficient history.

Model: scikit-learn Isolation Forest, 100 estimators, automatic contamination,
seed 42. Training data: aggregate daily counts for the 90 UTC days before the
selected month. Features: log scan volume, High/Critical fraction and Unknown
fraction. At least 30 active days and three distinct feature observations are
required. A negative decision margin marks unusual activity; it is not a threat
probability. Model and library versions and a training-data digest are saved.

No detection accuracy or production reliability claim follows from synthetic
tests. PostgreSQL deployment and live LLM/SMTP integration were not exercised.
The preview is isolated, contains synthetic history, and disables notifications.

Reference: [Official Isolation Forest documentation](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html).
