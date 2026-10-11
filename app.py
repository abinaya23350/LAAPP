
import os
import sys
import re
import time
import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from laapp_engine import mask_dataframe, analyze_text, PII_COLUMNS

st.set_page_config(
    page_title="LAAPP",
    page_icon="🔐",
    layout="wide"
)

@st.cache_resource
def get_analyzer():
    from presidio_analyzer import AnalyzerEngine
    return AnalyzerEngine()

def redact_text(text, result):
    spans = []

    for match in re.finditer(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        text
    ):
        spans.append((match.start(), match.end(), "EMAIL"))

    for match in re.finditer(
        r"(?<!\w)(?:\+?\d[\d\s().-]{7,}\d)(?!\w)",
        text
    ):
        spans.append((match.start(), match.end(), "PHONE"))

    for item in result["deep_findings"]:
        spans.append((
            item["start"],
            item["end"],
            item["entity"]
        ))

    spans.sort(key=lambda x: (x[0], -(x[1] - x[0])))

    selected = []
    for span in spans:
        if not selected or span[0] >= selected[-1][1]:
            selected.append(span)

    output = text
    for start, end, entity in reversed(selected):
        output = output[:start] + f"[MASKED:{entity}]" + output[end:]

    return output, selected

st.title("LAAPP")
st.subheader("Privacy-Aware Adaptive PII Detection and Anonymization")
st.write(
    "Detect potential personally identifiable information (PII), "
    "compare detection strategies, and protect structured CSV data."
)

strategy = st.sidebar.selectbox(
    "Detection Strategy",
    ["Static-fast", "Static-deep", "Adaptive"]
)

st.sidebar.markdown("### Strategy Guide")
st.sidebar.write("**Static-fast:** Email and phone pattern detection.")
st.sidebar.write("**Static-deep:** Uses Presidio for deeper entity detection.")
st.sidebar.write("**Adaptive:** Applies the prototype routing policy.")

text_tab, csv_tab = st.tabs(["Text Detection", "CSV Protection"])

with text_tab:
    st.header("Test Text for PII")
    user_text = st.text_area(
        "Enter text to analyze",
        placeholder="Example: Contact Abinaya at abinaya@example.com or 9876543210",
        height=130
    )

    if st.button("Analyze Text", type="primary"):
        if not user_text.strip():
            st.warning("Please enter some text first.")
        else:
            try:
                with st.spinner("Analyzing text..."):
                    analyzer = get_analyzer()
                    result = analyze_text(user_text, strategy, analyzer)
                    masked_text, spans = redact_text(user_text, result)

                st.subheader("Analysis Results")

                c1, c2, c3 = st.columns(3)
                c1.metric("Strategy", result["strategy"])
                c2.metric("Escalated to Deep Analysis",
                          "Yes" if result["escalated"] else "No")
                c3.metric("Latency", f'{result["latency_ms"]:.3f} ms')

                st.markdown("**Masked Text**")
                st.code(masked_text)

                st.markdown("**Fast Detection Findings**")
                st.write(result["fast_findings"] or "No email/phone patterns detected.")

                st.markdown("**Deep Detection Findings**")
                if result["deep_findings"]:
                    st.dataframe(
                        pd.DataFrame(result["deep_findings"]),
                        use_container_width=True
                    )
                else:
                    st.write("No deep-analysis findings returned.")

                st.caption(
                    f"Overlapping detections are merged for display. "
                    f"{len(spans)} text span(s) masked. "
                    "This prototype may miss PII; do not use it for real sensitive data."
                )

            except Exception as e:
                st.error(f"Analysis failed: {e}")
                st.info(
                    "Check that Presidio and its language model are installed "
                    "and initialized in this Colab runtime."
                )

with csv_tab:
    st.header("Protect Structured CSV Data")
    st.write(
        "Upload a CSV file. Values in recognized PII columns are replaced "
        "with [MASKED]. Other columns are retained."
    )

    uploaded_file = st.file_uploader("Upload CSV", type=["csv"])

    if uploaded_file is not None:
        try:
            source_df = pd.read_csv(uploaded_file)
            st.write(f"Uploaded dataset: **{len(source_df):,} records**")
            st.write("Original data preview")
            st.dataframe(source_df.head(10), use_container_width=True)

            found_columns = [
                col for col in PII_COLUMNS if col in source_df.columns
            ]

            st.write("Recognized PII columns:", found_columns or "None found")

            if st.button("Protect CSV", type="primary"):
                start = time.perf_counter()
                protected_df = mask_dataframe(source_df)
                elapsed = time.perf_counter() - start

                st.session_state["protected_df"] = protected_df
                st.session_state["csv_metrics"] = {
                    "records": len(source_df),
                    "columns": found_columns,
                    "elapsed": elapsed
                }

        except Exception as e:
            st.error(f"Could not read this CSV: {e}")

    if "protected_df" in st.session_state:
        protected_df = st.session_state["protected_df"]
        metrics = st.session_state["csv_metrics"]
        elapsed = metrics["elapsed"]
        throughput = metrics["records"] / elapsed if elapsed > 0 else 0

        st.subheader("Protected Dataset Preview")

        c1, c2, c3 = st.columns(3)
        c1.metric("Records Processed", f'{metrics["records"]:,}')
        c2.metric("Processing Time", f"{elapsed:.4f} seconds")
        c3.metric("Processing Throughput", f"{throughput:,.0f} records/sec")

        st.dataframe(protected_df.head(10), use_container_width=True)

        csv_bytes = protected_df.to_csv(index=False).encode("utf-8")

        st.download_button(
            "Download Protected CSV",
            data=csv_bytes,
            file_name="laapp_protected.csv",
            mime="text/csv"
        )

        st.caption(
            "Prototype note: column-based masking is applied to recognized "
            "PII fields. Review the output before using it. This is not a "
            "certified privacy guarantee."
        )

st.divider()
st.caption("LAAPP | Prototype for privacy-aware PII detection and masking")
