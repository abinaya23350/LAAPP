# LAAPP

LAAPP is a prototype pipeline for adaptive PII detection and redaction using fast pattern-based detection, deeper NER analysis, risk scoring, escalation and fallback masking.

## Project contents

- `laapp_controller_v3.py`: updated adaptive controller and risk scoring
- `laapp_engine.py`: application engine
- `app.py`: application interface
- `LAAPP_multibatch_experiment_v2.ipynb`: experiment notebook (outputs cleared in this copy)
- CSV summaries and PNG figures: selected experiment results

## Setup

Use Python 3.12 in a virtual environment where possible.

```bash
python -m venv .venv
```

Activate the environment, then run:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Presidio may require an English spaCy model. Install the model required by your controller configuration before running the app.

## Important

This is a prototype, not a formal privacy guarantee. Review the evaluation results and test for missed PII before real-world use.

The original dataset and masked record-level datasets are not included. Do not publish private or identifiable data, API keys, or credentials.
