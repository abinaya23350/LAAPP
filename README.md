# LAAPP
# LAAPP — Latency-Aware Adaptive PII Detection and Redaction Pipeline

## Project Overview

LAAPP is a prototype privacy pipeline designed to detect and redact Personally Identifiable Information (PII) from text. It combines fast pattern-based detection, deeper Named Entity Recognition (NER), risk-based escalation, and fallback masking.

The goal is to explore how adaptive detection and fallback protection can be used to balance processing latency and PII protection.

## Problem Statement

Traditional PII detection pipelines may apply expensive detection methods to every record, increasing processing time. Fast pattern-based methods can be efficient but may miss contextual information such as personal names.

LAAPP explores a staged approach in which records are assigned risk scores, selected records are escalated for deeper analysis, and fallback masking is used for eligible records that are not escalated.

## Key Features

- **Fast detection:** Pattern-based detection for common structured PII.
- **Deep detection:** Presidio-based analysis for supported entity types.
- **Risk scoring:** Assigns heuristic risk scores to incoming text.
- **Adaptive escalation:** Selects records for deeper analysis based on risk ranking and the controller's escalation ratio.
- **Fallback masking:** Applies heuristic masking to eligible non-escalated records.
- **Evaluation:** Supports comparison of detection strategies using latency, escalation, recall, leakage, precision, and overmasking metrics.

## Technology Stack

- Python
- Microsoft Presidio Analyzer and Anonymizer
- Regular expressions
- pandas
- Streamlit
- Jupyter Notebook / Google Colab

## Project Structure

| File | Description |
|---|---|
| `app.py` | Application interface |
| `laapp_engine.py` | LAAPP engine module |
| `laapp_controller.py` | Original controller |
| `laapp_controller_v2.py` | Version 2 controller |
| `laapp_controller_v3.py` | Updated controller with contextual name risk scoring |
| `LAAPP_multibatch_experiment_v2.ipynb` | Experiment notebook |
| `LAAPP_project_documentation.txt` | Project documentation |
| `evaluation_notes.txt` | Evaluation notes |
| `laapp_100k_aggregate_v2.csv` | Aggregate results from the 100,000-record experiment |
| `laapp_100k_batch_metrics_v2.csv` | Batch-level experiment metrics |
| `laapp_100k_batch_summary_v2.csv` | Batch-level summary |
| `laapp_evaluation_summary.csv` | Evaluation summary |
| `detection_strategy_comparison.csv` | Strategy comparison results |
| `baseline_validation.csv` | Baseline validation results |
| `requirements.txt` | Python dependencies |

## Installation

### 1. Clone the repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd LAAPP
```

Replace `<YOUR_GITHUB_REPOSITORY_URL>` with your actual repository URL.

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Presidio may require an English spaCy model, depending on the configured recognizers. Install the model required by your controller configuration if it is not already available.

## Running the Application

If `app.py` is configured as a Streamlit application, run:

```bash
streamlit run app.py
```

The experiment notebook can be opened in Jupyter Notebook or Google Colab. Review the notebook cells and configure the dataset path before running an experiment.

## Evaluation Metrics

LAAPP experiments include the following metrics:

- **Latency:** Time required to process records.
- **Escalation rate:** Proportion of records sent for deeper analysis.
- **Recall:** Proportion of relevant PII detections successfully identified.
- **Leakage rate:** Proportion of relevant PII detections missed by the pipeline, according to the experiment's evaluation method.
- **Precision:** Proportion of reported detections that are correct.
- **Overmasking rate:** Measures unnecessary masking according to the evaluation method.

Refer to the supplied experiment CSV files and evaluation notes for the measured results. Results depend on the dataset, controller configuration, and evaluation methodology.

## Important Limitations

- LAAPP is a prototype and does not provide a formal privacy guarantee.
- The contextual name detector uses heuristics and may miss names that do not match its patterns.
- Fallback masking may produce false positives or false negatives.
- Performance and detection quality should be validated on representative datasets before deployment.
- The current experiment results should not be interpreted as proof that LAAPP outperforms every baseline.

## Data Privacy

Do not upload raw datasets containing personal information, record-level masked datasets, API keys, passwords, or other sensitive information to a public repository.

Only publish datasets when you have verified that you have permission to share them.

## Future Improvements

- Improve contextual PII detection and reduce false positives.
- Evaluate recall and leakage across more diverse datasets.
- Improve the adaptive controller using validated quality and latency measurements.
- Integrate and evaluate a distributed Kafka–Spark processing pipeline.
- Compare the approach with additional baseline methods.

## Authors

Project team — update this section with your team members' names and affiliations.

## License

Add an appropriate license before distributing the project publicly.
