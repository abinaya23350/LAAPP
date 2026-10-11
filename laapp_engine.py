
import re
import time
import pandas as pd

PII_COLUMNS = [
    "firstname", "lastname", "street", "streetnumber",
    "address_unit", "postalcode", "city", "phone", "email"
]

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
PHONE_PATTERN = re.compile(
    r"(?<!\w)(?:\+?\d[\d\s().-]{7,}\d)(?!\w)"
)


def mask_dataframe(dataframe):
    result = dataframe.copy(deep=True)

    for column in PII_COLUMNS:
        if column in result.columns:
            nonempty = (
                result[column].notna()
                & result[column].astype(str).str.strip().ne("")
            )
            result.loc[nonempty, column] = "[MASKED]"

    return result


def fast_detect(text):
    text = str(text)
    findings = []

    if EMAIL_PATTERN.search(text):
        findings.append("EMAIL_ADDRESS")

    if PHONE_PATTERN.search(text):
        findings.append("PHONE_NUMBER")

    return findings


def deep_detect(text, analyzer):
    results = analyzer.analyze(
        text=str(text),
        language="en"
    )

    return [
        {
            "entity": item.entity_type,
            "start": item.start,
            "end": item.end,
            "score": round(float(item.score), 3)
        }
        for item in results
    ]


def analyze_text(text, strategy, analyzer):
    start = time.perf_counter()

    fast_results = fast_detect(text)
    deep_results = []
    escalated = False

    if strategy == "Static-fast":
        pass

    elif strategy == "Static-deep":
        deep_results = deep_detect(text, analyzer)
        escalated = True

    elif strategy == "Adaptive":
        # Conservative fallback: if fast patterns do not match,
        # use deeper analysis for non-empty alphabetic text.
        # This is a prototype policy, not a privacy guarantee.
        should_escalate = bool(fast_results) or bool(
            re.search(r"[A-Za-z]", str(text))
        )

        if should_escalate:
            deep_results = deep_detect(text, analyzer)
            escalated = True

    else:
        raise ValueError("Unknown detection strategy")

    elapsed = time.perf_counter() - start

    return {
        "strategy": strategy,
        "fast_findings": fast_results,
        "deep_findings": deep_results,
        "escalated": escalated,
        "latency_ms": round(elapsed * 1000, 3)
    }
