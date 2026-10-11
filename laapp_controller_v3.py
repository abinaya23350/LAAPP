"""LAAPP experimental controller.

Prototype for comparing fast rules, Presidio escalation, risk-based selection,
and conservative fallback masking. This is an experimental system, not a
formal privacy guarantee.
"""

import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pandas as pd


PII_COLUMNS = [
    "firstname",
    "lastname",
    "street",
    "streetnumber",
    "address_unit",
    "postalcode",
    "city",
    "phone",
    "email",
]

EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d\s().-]{7,}\d)(?!\w)")
ZIP_RE = re.compile(r"(?<!\d)\d{5,6}(?!\d)")
STREET_RE = re.compile(
    r"\b\d{1,5}\s+[A-Za-z][A-Za-z0-9.' -]{1,45}\s"
    r"(?:Street|St|Road|Rd|Avenue|Ave|Lane|Ln|Drive|Dr|Boulevard|Blvd)\b",
    re.IGNORECASE,
)


@dataclass
class ControllerState:
    """Simple AIMD-style controller state for experiments."""

    rho: float = 0.30
    latency_limit_s: float = 0.55
    min_rho: float = 0.05
    max_rho: float = 1.0
    decrease_factor: float = 0.70
    increase_step: float = 0.05

    def update(self, observed_batch_latency_s: float) -> float:
        """Reduce escalation ratio when over budget; otherwise increase slowly."""
        if observed_batch_latency_s > self.latency_limit_s:
            self.rho = max(self.min_rho, self.rho * self.decrease_factor)
        else:
            self.rho = min(self.max_rho, self.rho + self.increase_step)
        return self.rho


def _deduplicate(spans: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove exact duplicate spans while preserving the longest-first ordering."""
    seen = set()
    result = []
    for item in sorted(
        spans,
        key=lambda x: (
            int(x["start"]),
            -(int(x["end"]) - int(x["start"])),
            str(x.get("entity", "")),
        ),
    ):
        key = (int(item["start"]), int(item["end"]), str(item["entity"]))
        if key not in seen:
            seen.add(key)
            result.append(dict(item))
    return result


def fast_detect(text: str) -> List[Dict[str, Any]]:
    """Detect common structured PII patterns using lightweight regular expressions."""
    text = str(text)
    hits: List[Dict[str, Any]] = []
    patterns = [
        ("EMAIL_ADDRESS", EMAIL_RE),
        ("PHONE_NUMBER", PHONE_RE),
        ("POSTAL_CODE", ZIP_RE),
        ("STREET_ADDRESS", STREET_RE),
    ]
    for label, pattern in patterns:
        for match in pattern.finditer(text):
            hits.append(
                {
                    "entity": label,
                    "start": match.start(),
                    "end": match.end(),
                    "score": 1.0,
                    "source": "regex",
                }
            )
    return _deduplicate(hits)


def deep_detect(text: str, analyzer: Any) -> List[Dict[str, Any]]:
    """Run Presidio when an analyzer is supplied; keep relevant entity types."""
    if analyzer is None:
        return []

    allowed = {
        "PERSON",
        "LOCATION",
        "GPE",
        "PHONE_NUMBER",
        "EMAIL_ADDRESS",
        "STREET_ADDRESS",
        "POSTAL_CODE",
    }
    raw_results = analyzer.analyze(text=str(text), language="en")
    results = []
    for item in raw_results:
        entity = str(item.entity_type)
        if entity not in allowed:
            continue
        results.append(
            {
                "entity": entity,
                "start": int(item.start),
                "end": int(item.end),
                "score": round(float(item.score), 4),
                "source": "presidio",
            }
        )
    return _deduplicate(results)


def risk_score(text: str, fast_hits: list) -> float:
    """Heuristic risk score with contextual name candidates."""
    text = str(text)
    score = 0.65 if fast_hits else 0.0

    if re.search(
        r"\b(name|email|phone|address|contact|street|postcode|zip)\b",
        text, re.I
    ):
        score += 0.25

    match = re.search(
        r"\b(?:to|contact|email|call|reach)\s+"
        r"([A-Z][a-z]{1,})\s+([A-Z][a-z]{1,})\b",
        text, re.IGNORECASE
    )
    if match and match.group(1)[0].isupper() and match.group(2)[0].isupper():
        score = max(score, 0.65)

    if re.search(r"\b[A-Z][a-z]{2,}\b", text):
        score += 0.10

    if re.search(r"\d{3,}", text):
        score += 0.10

    return min(1.0, score)

def fail_closed_spans(text: str) -> List[Dict[str, Any]]:
    """Heuristic fallback for structured PII and contextual name candidates."""
    text = str(text)
    spans = []

    patterns = [
        (EMAIL_RE, "EMAIL_ADDRESS"),
        (PHONE_RE, "PHONE_NUMBER"),
        (ZIP_RE, "POSTAL_CODE"),
        (STREET_RE, "STREET_ADDRESS"),
        (re.compile(r"\b\d[\d\s().+-]{2,}\d\b"), "FALLBACK_DIGITS"),
    ]

    for pattern, label in patterns:
        for match in pattern.finditer(text):
            spans.append({
                "entity": label,
                "start": match.start(),
                "end": match.end(),
                "score": 1.0,
                "source": "fail_closed",
            })

    name_pattern = re.compile(
        r"\b(?:to|contact|email|call|reach)\s+"
        r"([A-Z][a-z]{1,})\s+([A-Z][a-z]{1,})\b",
        re.IGNORECASE
    )

    for match in name_pattern.finditer(text):
        first, last = match.group(1), match.group(2)
        if first[0].isupper() and last[0].isupper():
            spans.append({
                "entity": "FALLBACK_PERSON_CANDIDATE",
                "start": match.start(1),
                "end": match.end(2),
                "score": 0.70,
                "source": "context_heuristic",
            })

    return _deduplicate(spans)

def redact_spans(
    text: str,
    spans: Sequence[Dict[str, Any]],
    replacement: str = "[MASKED]",
) -> str:
    """Replace valid spans, merging overlaps to avoid offset corruption."""
    text = str(text)
    valid = []
    for span in spans:
        start = int(span["start"])
        end = int(span["end"])
        if 0 <= start < end <= len(text):
            valid.append((start, end))

    merged: List[Tuple[int, int]] = []
    for start, end in sorted(valid):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))

    for start, end in reversed(merged):
        text = text[:start] + replacement + text[end:]
    return text


def mask_dataframe(dataframe: pd.DataFrame) -> pd.DataFrame:
    """Mask non-empty values in known PII columns without dtype warnings.

    The source DataFrame is not modified. PII columns are converted to pandas'
    nullable string dtype, then masked with Series.mask instead of assigning a
    string into an integer column via .loc. Empty and missing values remain
    empty/missing. Non-PII columns are preserved unchanged.
    """
    result = dataframe.copy(deep=True)

    for col in PII_COLUMNS:
        if col not in result.columns:
            continue

        # Nullable string dtype supports "[MASKED]" and missing values safely.
        values = result[col].astype("string")
        nonempty = values.notna() & values.str.strip().ne("")
        result[col] = values.mask(nonempty, "[MASKED]")

    return result


def build_record_text(row: pd.Series) -> str:
    """Build a text representation from available structured PII fields."""
    fields = PII_COLUMNS
    return " | ".join(
        f"{col}: {row[col]}"
        for col in fields
        if col in row.index
        and pd.notna(row[col])
        and str(row[col]).strip()
    )


def run_batch(
    texts: Sequence[str],
    analyzer: Any,
    state: Optional[ControllerState] = None,
    strategy: str = "LAAPP",
    threshold: float = 0.55,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Run one batch using one of the six benchmark strategies.

    Strategies:
      Static-fast: regex-only.
      Static-deep: Presidio on every record plus regex findings.
      Threshold: Presidio only for records meeting the risk threshold.
      Static-rho-fail-closed: fixed 30% deep-detection budget plus fallback.
      LAAPP-no-fail-closed: adaptive rho, no fallback masking.
      LAAPP: adaptive rho and fallback masking for high-risk non-escalated rows.
    """
    if state is None:
        state = ControllerState()

    allowed_strategies = {
        "Static-fast",
        "Static-deep",
        "Threshold",
        "Static-rho-fail-closed",
        "LAAPP-no-fail-closed",
        "LAAPP",
    }
    if strategy not in allowed_strategies:
        raise ValueError(f"Unknown strategy: {strategy}")

    start_time = time.perf_counter()
    scored = []
    for index, text in enumerate(texts):
        text = str(text)
        fast_hits = fast_detect(text)
        scored.append((index, text, fast_hits, risk_score(text, fast_hits)))

    count = len(scored)

    if strategy == "Static-deep":
        selected = set(range(count))
    elif strategy == "Threshold":
        selected = {
            index for index, _, _, risk in scored if risk >= threshold
        }
    elif strategy == "Static-fast":
        selected = set()
    else:
        rho = (
            0.30
            if strategy == "Static-rho-fail-closed"
            else state.rho
        )
        selected_count = min(count, max(0, int(round(rho * count))))
        ranked = sorted(scored, key=lambda row: row[3], reverse=True)
        selected = {row[0] for row in ranked[:selected_count]}

    records = []
    for index, text, fast_hits, risk in scored:
        escalated = index in selected
        deep_hits = deep_detect(text, analyzer) if escalated else []
        spans = list(fast_hits) + list(deep_hits)
        used_fallback = False

        if (
            strategy in {"Static-rho-fail-closed", "LAAPP"}
            and risk >= threshold
            and not escalated
        ):
            spans.extend(fail_closed_spans(text))
            used_fallback = True

        if strategy == "Static-fast":
            spans = list(fast_hits)
        elif strategy == "Threshold" and not escalated:
            spans = list(fast_hits)

        spans = _deduplicate(spans)
        records.append(
            {
                "index": index,
                "text": text,
                "redacted_text": redact_spans(text, spans),
                "risk_score": round(risk, 3),
                "fast_findings": fast_hits,
                "deep_findings": deep_hits,
                "escalated": escalated,
                "fail_closed": used_fallback,
                "spans": spans,
            }
        )

    elapsed = time.perf_counter() - start_time
    # Only adaptive strategies update rho. Static baselines must remain fixed.
    if strategy in {"LAAPP", "LAAPP-no-fail-closed"}:
        state.update(elapsed)

    escalated_count = sum(record["escalated"] for record in records)
    summary = {
        "strategy": strategy,
        "records": count,
        "batch_latency_s": round(elapsed, 6),
        "avg_latency_ms": round(elapsed * 1000 / max(count, 1), 4),
        "throughput_records_s": round(count / max(elapsed, 1e-9), 3),
        "escalated_records": escalated_count,
        "escalation_rate": round(escalated_count / max(count, 1), 4),
        "fail_closed_records": sum(record["fail_closed"] for record in records),
        "rho_after_update": round(state.rho, 4),
        "latency_limit_s": state.latency_limit_s,
    }
    return records, summary


def evaluate_spans(
    records: Sequence[Dict[str, Any]],
    ground_truth: Sequence[Sequence[Tuple[int, int]]],
) -> Dict[str, Any]:
    """Evaluate character-level recall, leakage, precision, and over-masking."""
    gold_characters = 0
    covered_characters = 0
    predicted_characters = 0
    false_positive_characters = 0
    total_text_characters = 0

    for record, gold_spans in zip(records, ground_truth):
        text = record["text"]
        gold = set()
        predicted = set()

        for start, end in gold_spans:
            gold.update(range(max(0, start), min(len(text), end)))

        for span in record["spans"]:
            start = max(0, int(span["start"]))
            end = min(len(text), int(span["end"]))
            predicted.update(range(start, end))

        gold_characters += len(gold)
        covered_characters += len(gold & predicted)
        predicted_characters += len(predicted)
        false_positive_characters += len(predicted - gold)
        total_text_characters += len(text)

    recall = (
        covered_characters / gold_characters if gold_characters else 1.0
    )
    precision = (
        covered_characters / predicted_characters
        if predicted_characters
        else (1.0 if not gold_characters else 0.0)
    )

    return {
        "character_recall": round(recall, 4),
        "character_leakage": round(1 - recall if gold_characters else 0, 4),
        "character_precision": round(precision, 4),
        "overmask_fraction_of_text": round(
            false_positive_characters / max(total_text_characters, 1), 4
        ),
        "gold_pii_characters": gold_characters,
        "covered_pii_characters": covered_characters,
        "predicted_characters": predicted_characters,
    }
