import streamlit as st
import pandas as pd
import numpy as np
import joblib
import shap
import matplotlib.pyplot as plt

from pathlib import Path
from sklearn.metrics import confusion_matrix


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="AI-Driven Military Cybersecurity",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================
# PATH CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "dashboard_data"

MODEL_PATH = DATA_DIR / "attack_xgb_model.pkl"
FEATURE_PATH = DATA_DIR / "feature_names.pkl"

ATTACK_DISTRIBUTION_PATH = DATA_DIR / "attack_distribution.csv"
RISK_DISTRIBUTION_PATH = DATA_DIR / "risk_distribution.csv"
RISK_RESULTS_PATH = DATA_DIR / "risk_results.csv"
SHAP_PATH = DATA_DIR / "shap_feature_importance.csv"


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>

    .main {
        background-color: #0e1117;
    }

    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }

    .metric-card {
        background: #111827;
        border: 1px solid #263244;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
    }

    .metric-title {
        color: #9ca3af;
        font-size: 14px;
        margin-bottom: 8px;
    }

    .metric-value {
        color: white;
        font-size: 30px;
        font-weight: 700;
    }

    .critical {
        color: #ff4b4b;
        font-weight: bold;
    }

    .high {
        color: #ff8c42;
        font-weight: bold;
    }

    .medium {
        color: #f4c542;
        font-weight: bold;
    }

    .low {
        color: #55d187;
        font-weight: bold;
    }

    .alert-box {
        padding: 18px;
        border-radius: 10px;
        margin-top: 10px;
        margin-bottom: 10px;
    }

    .pipeline {
        background: #111827;
        border-radius: 12px;
        padding: 20px;
        border: 1px solid #263244;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# ATTACK CLASS MAPPING
# ============================================================

ATTACK_CLASSES = [
    "Analysis",
    "Backdoor",
    "DoS",
    "Exploits",
    "Fuzzers",
    "Generic",
    "Reconnaissance",
    "Shellcode",
    "Worms"
]


# ============================================================
# SEVERITY MAPPING
# ============================================================

ATTACK_SEVERITY_MAP = {
    "Analysis": "Low",
    "Fuzzers": "Medium",
    "Reconnaissance": "Medium",
    "Generic": "Medium",
    "DoS": "High",
    "Exploits": "High",
    "Backdoor": "Critical",
    "Shellcode": "Critical",
    "Worms": "Critical"
}


SEVERITY_SCORE_MAP = {
    "Low": 1.0,
    "Medium": 2.0,
    "High": 3.0,
    "Critical": 4.0
}


# ============================================================
# LOAD MODEL
# ============================================================

@st.cache_resource
def load_model():

    if not MODEL_PATH.exists():
        return None

    try:
        model = joblib.load(MODEL_PATH)
        return model

    except Exception as e:
        st.error(f"Unable to load XGBoost model: {e}")
        return None


# ============================================================
# LOAD FEATURE NAMES
# ============================================================

@st.cache_resource
def load_feature_names():

    if not FEATURE_PATH.exists():
        return None

    try:
        features = joblib.load(FEATURE_PATH)

        if isinstance(features, np.ndarray):
            features = features.tolist()

        return list(features)

    except Exception as e:
        st.error(f"Unable to load feature names: {e}")
        return None


# ============================================================
# LOAD DASHBOARD DATA
# ============================================================

@st.cache_data
def load_csv(path):

    if not path.exists():
        return None

    try:
        return pd.read_csv(path)

    except Exception:
        return None


attack_distribution = load_csv(
    ATTACK_DISTRIBUTION_PATH
)

risk_distribution = load_csv(
    RISK_DISTRIBUTION_PATH
)

risk_results = load_csv(
    RISK_RESULTS_PATH
)

shap_feature_importance = load_csv(
    SHAP_PATH
)


# ============================================================
# LOAD MODEL AND FEATURES
# ============================================================

attack_xgb_model = load_model()

feature_names = load_feature_names()


# ============================================================
# RISK SCORE FUNCTION
# ============================================================

def calculate_risk_score(
    attack_type,
    confidence
):

    base_severity = ATTACK_SEVERITY_MAP.get(
        attack_type,
        "Medium"
    )

    base_score = SEVERITY_SCORE_MAP[
        base_severity
    ]

    if confidence >= 0.90:

        confidence_factor = 1.0

    elif confidence >= 0.75:

        confidence_factor = 0.90

    elif confidence >= 0.60:

        confidence_factor = 0.75

    else:

        confidence_factor = 0.60

    risk_score = (
        base_score *
        confidence_factor
    )

    if risk_score >= 3.5:

        risk_level = "Critical"

    elif risk_score >= 2.5:

        risk_level = "High"

    elif risk_score >= 1.5:

        risk_level = "Medium"

    else:

        risk_level = "Low"

    return risk_score, risk_level


# ============================================================
# SECURITY ALERT FUNCTION
# ============================================================

def generate_security_alert(
    attack_type,
    confidence,
    risk_level
):

    if risk_level == "Critical":

        priority = "IMMEDIATE ACTION"

    elif risk_level == "High":

        priority = "HIGH PRIORITY"

    elif risk_level == "Medium":

        priority = "MONITOR"

    else:

        priority = "LOW PRIORITY"

    return {
        "Threat": attack_type,
        "Confidence": round(
            confidence * 100,
            2
        ),
        "Risk Level": risk_level,
        "Priority": priority
    }


# ============================================================
# PAGE HEADER
# ============================================================

st.sidebar.title("🛡️ Security Control")

st.sidebar.markdown(
    "### Navigate"
)


# ============================================================
# NAVIGATION
# ============================================================

page = st.sidebar.radio(
    "",
    [
        "🏠 Security Overview",
        "🎯 Attack Analysis",
        "🚨 Threat Risk",
        "🧠 Explainable AI",
        "🔔 Security Alerts",
        "📄 Threat Data",
        "🔬 Live Threat Analysis"
    ]
)


# ============================================================
# SIDEBAR PIPELINE
# ============================================================

st.sidebar.markdown("---")

st.sidebar.markdown(
    "### System Pipeline"
)

st.sidebar.markdown(
    """
    🌐 Network Traffic

    ↓

    ⚙️ XGBoost Detection

    ↓

    🎯 Attack Classification

    ↓

    🧠 SHAP Explanation

    ↓

    📊 Risk Scoring

    ↓

    🚨 Security Alert
    """
)


# ============================================================
# HEADER
# ============================================================

st.markdown(
    "# 🛡️ AI-Driven Security Framework"
)

st.markdown(
    "## Secure Military Information Systems"
)

st.markdown(
    """
    AI-powered network threat detection, attack classification,
    explainable AI, risk assessment and security alerting.
    """
)

st.divider()


# ============================================================
# PAGE 1 — SECURITY OVERVIEW
# ============================================================

if page == "🏠 Security Overview":

    st.header("🏠 Security Overview")

    # ---------------------------------------------
    # Calculate statistics
    # ---------------------------------------------

    total_events = 45332

    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    if risk_distribution is not None:

        columns = [
            c.lower()
            for c in risk_distribution.columns
        ]

        level_col = None
        count_col = None

        for c in risk_distribution.columns:

            if "risk" in c.lower():
                level_col = c

            if (
                "count" in c.lower()
                or "number" in c.lower()
                or "value" in c.lower()
            ):
                count_col = c

        if level_col and count_col:

            for _, row in risk_distribution.iterrows():

                level = str(
                    row[level_col]
                )

                count = int(
                    row[count_col]
                )

                if level == "Critical":
                    critical_count = count

                elif level == "High":
                    high_count = count

                elif level == "Medium":
                    medium_count = count

                elif level == "Low":
                    low_count = count

    elif risk_results is not None:

        if "Risk Level" in risk_results.columns:

            counts = (
                risk_results[
                    "Risk Level"
                ]
                .value_counts()
            )

            critical_count = int(
                counts.get(
                    "Critical",
                    0
                )
            )

            high_count = int(
                counts.get(
                    "High",
                    0
                )
            )

            medium_count = int(
                counts.get(
                    "Medium",
                    0
                )
            )

            low_count = int(
                counts.get(
                    "Low",
                    0
                )
            )

            total_events = len(
                risk_results
            )

    # ---------------------------------------------
    # Metrics
    # ---------------------------------------------

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:

        st.metric(
            "🌐 Events Analyzed",
            f"{total_events:,}"
        )

    with col2:

        st.metric(
            "🚨 Critical",
            f"{critical_count:,}"
        )

    with col3:

        st.metric(
            "🔴 High Risk",
            f"{high_count:,}"
        )

    with col4:

        st.metric(
            "🟡 Medium Risk",
            f"{medium_count:,}"
        )

    with col5:

        st.metric(
            "🎯 Attack Classes",
            "9"
        )

    st.divider()

    # ---------------------------------------------
    # Pipeline
    # ---------------------------------------------

    st.subheader(
        "🔄 AI Security Pipeline"
    )

    pipeline_cols = st.columns(7)

    pipeline_items = [
        "🌐\nNetwork Traffic",
        "⚙️\nXGBoost",
        "🎯\nClassification",
        "🧠\nSHAP",
        "📊\nRisk Score",
        "🚨\nAlert",
        "🛡️\nResponse"
    ]

    for col, item in zip(
        pipeline_cols,
        pipeline_items
    ):

        with col:

            st.info(item)

    st.divider()

    # ---------------------------------------------
    # Charts
    # ---------------------------------------------

    left, right = st.columns(2)

    with left:

        st.subheader(
            "🎯 Attack Type Distribution"
        )

        if attack_distribution is not None:

            st.dataframe(
                attack_distribution,
                use_container_width=True
            )

            numeric_columns = (
                attack_distribution
                .select_dtypes(
                    include=np.number
                )
                .columns
            )

            if len(numeric_columns) > 0:

                st.bar_chart(
                    attack_distribution[
                        numeric_columns
                    ]
                )

        else:

            st.info(
                "Attack distribution data not found."
            )

    with right:

        st.subheader(
            "🚨 Threat Severity"
        )

        if risk_results is not None:

            if "Risk Level" in risk_results.columns:

                risk_counts = (
                    risk_results[
                        "Risk Level"
                    ]
                    .value_counts()
                )

                st.bar_chart(
                    risk_counts
                )

        elif risk_distribution is not None:

            st.dataframe(
                risk_distribution,
                use_container_width=True
            )

        else:

            st.info(
                "Risk distribution data not found."
            )


# ============================================================
# PAGE 2 — ATTACK ANALYSIS
# ============================================================

elif page == "🎯 Attack Analysis":

    st.header(
        "🎯 Attack Classification Analysis"
    )

    st.markdown(
        """
        The trained XGBoost model classifies malicious
        network traffic into nine attack categories.
        """
    )

    attack_info = pd.DataFrame({

        "Class ID": range(9),

        "Attack Type": ATTACK_CLASSES,

        "Severity": [
            ATTACK_SEVERITY_MAP[x]
            for x in ATTACK_CLASSES
        ]

    })

    st.dataframe(
        attack_info,
        use_container_width=True,
        hide_index=True
    )

    st.subheader(
        "📊 Attack Distribution"
    )

    if attack_distribution is not None:

        st.dataframe(
            attack_distribution,
            use_container_width=True
        )

        numeric_cols = (
            attack_distribution
            .select_dtypes(
                include=np.number
            )
            .columns
        )

        if len(numeric_cols) > 0:

            st.bar_chart(
                attack_distribution[
                    numeric_cols
                ]
            )

    else:

        st.warning(
            "attack_distribution.csv was not found."
        )


# ============================================================
# PAGE 3 — THREAT RISK
# ============================================================

elif page == "🚨 Threat Risk":

    st.header(
        "🚨 Threat Severity & Risk Scoring"
    )

    st.markdown(
        """
        Risk is calculated using the predicted attack type
        and the model's prediction confidence.
        """
    )

    severity_df = pd.DataFrame({

        "Attack Type": ATTACK_CLASSES,

        "Base Severity": [
            ATTACK_SEVERITY_MAP[x]
            for x in ATTACK_CLASSES
        ],

        "Base Score": [
            SEVERITY_SCORE_MAP[
                ATTACK_SEVERITY_MAP[x]
            ]
            for x in ATTACK_CLASSES
        ]

    })

    st.dataframe(
        severity_df,
        use_container_width=True,
        hide_index=True
    )

    st.subheader(
        "📊 Risk Distribution"
    )

    if risk_results is not None:

        if "Risk Level" in risk_results.columns:

            counts = (
                risk_results[
                    "Risk Level"
                ]
                .value_counts()
            )

            col1, col2, col3, col4 = st.columns(4)

            with col1:
                st.metric(
                    "🟢 Low",
                    f"{counts.get('Low', 0):,}"
                )

            with col2:
                st.metric(
                    "🟡 Medium",
                    f"{counts.get('Medium', 0):,}"
                )

            with col3:
                st.metric(
                    "🟠 High",
                    f"{counts.get('High', 0):,}"
                )

            with col4:
                st.metric(
                    "🔴 Critical",
                    f"{counts.get('Critical', 0):,}"
                )

            st.bar_chart(
                counts
            )

            st.subheader(
                "🎯 Attack Type vs Risk Level"
            )

            if "Attack Type" in risk_results.columns:

                cross_tab = pd.crosstab(
                    risk_results[
                        "Attack Type"
                    ],
                    risk_results[
                        "Risk Level"
                    ]
                )

                st.dataframe(
                    cross_tab,
                    use_container_width=True
                )

    else:

        st.warning(
            "risk_results.csv was not found."
        )


# ============================================================
# PAGE 4 — EXPLAINABLE AI
# ============================================================

elif page == "🧠 Explainable AI":

    st.header(
        "🧠 Explainable AI — SHAP"
    )

    st.markdown(
        """
        SHAP explains which network features contributed
        most strongly to the attack classification.
        """
    )

    if shap_feature_importance is not None:

        st.subheader(
            "Top Network Features Influencing Attack Classification"
        )

        st.dataframe(
            shap_feature_importance,
            use_container_width=True,
            hide_index=True
        )

        if (
            "Feature"
            in shap_feature_importance.columns
            and
            "Mean Absolute SHAP"
            in shap_feature_importance.columns
        ):

            plot_df = (
                shap_feature_importance
                .head(20)
                .sort_values(
                    "Mean Absolute SHAP"
                )
            )

            fig, ax = plt.subplots(
                figsize=(10, 7)
            )

            ax.barh(
                plot_df["Feature"],
                plot_df[
                    "Mean Absolute SHAP"
                ]
            )

            ax.set_title(
                "Top 20 Network Features Influencing Attack Classification"
            )

            ax.set_xlabel(
                "Mean Absolute SHAP Value"
            )

            ax.set_ylabel(
                "Network Feature"
            )

            st.pyplot(
                fig,
                use_container_width=True
            )

            plt.close(fig)

    else:

        st.warning(
            "shap_feature_importance.csv was not found."
        )

    st.info(
        """
        Higher Mean Absolute SHAP values indicate that
        the corresponding feature has greater influence
        on the model's attack classification decisions.
        """
    )


# ============================================================
# PAGE 5 — SECURITY ALERTS
# ============================================================

elif page == "🔔 Security Alerts":

    st.header(
        "🔔 Security Alerts"
    )

    if risk_results is not None:

        display_df = risk_results.copy()

        if "Confidence" in display_df.columns:

            display_df["Confidence"] = (
                display_df["Confidence"]
                .apply(
                    lambda x:
                    f"{float(x) * 100:.2f}%"
                    if float(x) <= 1
                    else f"{float(x):.2f}%"
                )
            )

        # -----------------------------------------
        # Critical alerts
        # -----------------------------------------

        if "Risk Level" in display_df.columns:

            critical = display_df[
                display_df[
                    "Risk Level"
                ] == "Critical"
            ]

            high = display_df[
                display_df[
                    "Risk Level"
                ] == "High"
            ]

            st.subheader(
                "🔴 Critical Threats"
            )

            st.metric(
                "Critical Alerts",
                len(critical)
            )

            if len(critical) > 0:

                st.dataframe(
                    critical.head(100),
                    use_container_width=True
                )

            st.subheader(
                "🟠 High Priority Threats"
            )

            st.metric(
                "High Alerts",
                len(high)
            )

            if len(high) > 0:

                st.dataframe(
                    high.head(100),
                    use_container_width=True
                )

    else:

        st.warning(
            "Risk results are not available."
        )


# ============================================================
# PAGE 6 — THREAT DATA
# ============================================================

elif page == "📄 Threat Data":

    st.header(
        "📄 Threat Detection Data"
    )

    if risk_results is not None:

        st.write(
            f"Total records: **{len(risk_results):,}**"
        )

        st.dataframe(
            risk_results.head(500),
            use_container_width=True,
            height=600
        )

        csv_data = (
            risk_results
            .to_csv(index=False)
            .encode("utf-8")
        )

        st.download_button(
            label="⬇️ Download Threat Data",
            data=csv_data,
            file_name="military_threat_results.csv",
            mime="text/csv"
        )

    else:

        st.warning(
            "risk_results.csv was not found."
        )


# ============================================================
# PAGE 7 — LIVE THREAT ANALYSIS
# ============================================================

elif page == "🔬 Live Threat Analysis":

    st.header(
        "🔬 Live Network Threat Analysis"
    )

    st.markdown(
        """
        Upload a processed network traffic CSV containing
        the **194 features used during model training**.
        """
    )

    # ---------------------------------------------
    # Check model
    # ---------------------------------------------

    if attack_xgb_model is None:

        st.error(
            "❌ Trained XGBoost model was not found."
        )

        st.info(
            f"Expected model:\n\n{MODEL_PATH}"
        )

        st.stop()

    if feature_names is None:

        st.error(
            "❌ Feature names were not found."
        )

        st.info(
            f"Expected feature file:\n\n{FEATURE_PATH}"
        )

        st.stop()

    st.success(
        "✅ XGBoost model and feature list loaded successfully."
    )

    st.write(
        f"Model expects **{len(feature_names)} features**."
    )

    # ---------------------------------------------
    # File upload
    # ---------------------------------------------

    uploaded_file = st.file_uploader(
        "📁 Upload Network Traffic CSV",
        type=["csv"]
    )

    if uploaded_file is None:

        st.info(
            "Upload a CSV file to begin threat detection."
        )

        st.markdown(
            """
            ### Required Pipeline

            `Network Traffic`

            ↓

            `194 Features`

            ↓

            `XGBoost`

            ↓

            `Attack Type`

            ↓

            `Confidence`

            ↓

            `Risk Score`

            ↓

            `SHAP Explanation`

            ↓

            `Security Alert`
            """
        )

    else:

        try:

            input_df = pd.read_csv(
                uploaded_file
            )

            st.success(
                f"CSV loaded successfully: "
                f"{input_df.shape[0]:,} rows × "
                f"{input_df.shape[1]:,} columns"
            )

            with st.expander(
                "👀 Preview Uploaded Data"
            ):

                st.dataframe(
                    input_df.head(10),
                    use_container_width=True
                )

            # -----------------------------------------
            # Check missing features
            # -----------------------------------------

            missing_features = [
                feature
                for feature in feature_names
                if feature not in input_df.columns
            ]

            if missing_features:

                st.error(
                    f"❌ {len(missing_features)} required "
                    f"features are missing."
                )

                st.write(
                    "Missing features:"
                )

                st.code(
                    "\n".join(
                        missing_features[:50]
                    )
                )

                st.stop()

            # -----------------------------------------
            # Select exact feature order
            # -----------------------------------------

            X_live = input_df[
                feature_names
            ].copy()

            # -----------------------------------------
            # Convert values to numeric
            # -----------------------------------------

            for column in X_live.columns:

                X_live[column] = pd.to_numeric(
                    X_live[column],
                    errors="coerce"
                )

            # -----------------------------------------
            # Handle missing numeric values
            # -----------------------------------------

            X_live = X_live.replace(
                [np.inf, -np.inf],
                np.nan
            )

            X_live = X_live.fillna(0)

            st.success(
                f"✅ Correct feature matrix created: "
                f"{X_live.shape[0]:,} × "
                f"{X_live.shape[1]:,}"
            )

            # -----------------------------------------
            # Run prediction
            # -----------------------------------------

            with st.spinner(
                "Running AI threat detection..."
            ):

                predictions = (
                    attack_xgb_model
                    .predict(X_live)
                )

                probabilities = (
                    attack_xgb_model
                    .predict_proba(X_live)
                )

            st.success(
                "✅ Threat detection completed."
            )

            # -----------------------------------------
            # Convert predictions
            # -----------------------------------------

            predicted_attack_types = []

            confidence_values = []

            risk_scores = []

            risk_levels = []

            priorities = []

            for i in range(
                len(predictions)
            ):

                class_id = int(
                    predictions[i]
                )

                if (
                    0 <= class_id
                    < len(ATTACK_CLASSES)
                ):

                    attack_type = (
                        ATTACK_CLASSES[
                            class_id
                        ]
                    )

                else:

                    attack_type = (
                        f"Class {class_id}"
                    )

                confidence = float(
                    np.max(
                        probabilities[i]
                    )
                )

                risk_score, risk_level = (
                    calculate_risk_score(
                        attack_type,
                        confidence
                    )
                )

                if risk_level == "Critical":

                    priority = (
                        "IMMEDIATE ACTION"
                    )

                elif risk_level == "High":

                    priority = (
                        "HIGH PRIORITY"
                    )

                elif risk_level == "Medium":

                    priority = "MONITOR"

                else:

                    priority = (
                        "LOW PRIORITY"
                    )

                predicted_attack_types.append(
                    attack_type
                )

                confidence_values.append(
                    confidence
                )

                risk_scores.append(
                    risk_score
                )

                risk_levels.append(
                    risk_level
                )

                priorities.append(
                    priority
                )

            # -----------------------------------------
            # Create result dataframe
            # -----------------------------------------

            results_df = pd.DataFrame({

                "Attack Type":
                    predicted_attack_types,

                "Confidence":
                    confidence_values,

                "Risk Score":
                    risk_scores,

                "Risk Level":
                    risk_levels,

                "Priority":
                    priorities

            })

            # -----------------------------------------
            # Overview metrics
            # -----------------------------------------

            st.divider()

            st.subheader(
                "📊 Detection Summary"
            )

            result_col1, result_col2, result_col3, result_col4 = (
                st.columns(4)
            )

            with result_col1:

                st.metric(
                    "🌐 Records Analyzed",
                    f"{len(results_df):,}"
                )

            with result_col2:

                st.metric(
                    "🔴 Critical",
                    f"{sum(results_df['Risk Level'] == 'Critical'):,}"
                )

            with result_col3:

                st.metric(
                    "🟠 High",
                    f"{sum(results_df['Risk Level'] == 'High'):,}"
                )

            with result_col4:

                st.metric(
                    "🟡 Medium",
                    f"{sum(results_df['Risk Level'] == 'Medium'):,}"
                )

            # -----------------------------------------
            # Attack distribution
            # -----------------------------------------

            st.divider()

            left, right = st.columns(2)

            with left:

                st.subheader(
                    "🎯 Predicted Attack Types"
                )

                attack_counts = (
                    results_df[
                        "Attack Type"
                    ]
                    .value_counts()
                )

                st.bar_chart(
                    attack_counts
                )

            with right:

                st.subheader(
                    "🚨 Risk Distribution"
                )

                risk_counts = (
                    results_df[
                        "Risk Level"
                    ]
                    .value_counts()
                )

                st.bar_chart(
                    risk_counts
                )

            # -----------------------------------------
            # Detailed results
            # -----------------------------------------

            st.divider()

            st.subheader(
                "📋 Detection Results"
            )

            formatted_results = (
                results_df.copy()
            )

            formatted_results[
                "Confidence"
            ] = (
                formatted_results[
                    "Confidence"
                ]
                * 100
            ).round(2)

            st.dataframe(
                formatted_results,
                use_container_width=True,
                height=500
            )

            # -----------------------------------------
            # Download results
            # -----------------------------------------

            result_csv = (
                results_df
                .to_csv(index=False)
                .encode("utf-8")
            )

            st.download_button(
                label="⬇️ Download Detection Results",
                data=result_csv,
                file_name="live_threat_detection_results.csv",
                mime="text/csv"
            )

            # =================================================
            # SELECT ONE RECORD FOR EXPLANATION
            # =================================================

            st.divider()

            st.header(
                "🧠 Explain Individual Threat"
            )

            selected_index = st.number_input(
                "Select record number",
                min_value=0,
                max_value=len(X_live) - 1,
                value=0,
                step=1
            )

            selected_row = X_live.iloc[
                [selected_index]
            ]

            selected_prediction = (
                predicted_attack_types[
                    selected_index
                ]
            )

            selected_confidence = (
                confidence_values[
                    selected_index
                ]
            )

            selected_risk = (
                risk_levels[
                    selected_index
                ]
            )

            selected_score = (
                risk_scores[
                    selected_index
                ]
            )

            # -----------------------------------------
            # Threat card
            # -----------------------------------------

            st.subheader(
                "🚨 Threat Assessment"
            )

            c1, c2, c3, c4 = st.columns(4)

            with c1:

                st.metric(
                    "Attack Type",
                    selected_prediction
                )

            with c2:

                st.metric(
                    "Confidence",
                    f"{selected_confidence * 100:.2f}%"
                )

            with c3:

                st.metric(
                    "Risk Score",
                    f"{selected_score:.2f}"
                )

            with c4:

                st.metric(
                    "Risk Level",
                    selected_risk
                )

            # -----------------------------------------
            # Security alert
            # -----------------------------------------

            alert = generate_security_alert(
                selected_prediction,
                selected_confidence,
                selected_risk
            )

            if selected_risk == "Critical":

                st.error(
                    f"🚨 {alert['Priority']} — "
                    f"{alert['Threat']} detected "
                    f"with {alert['Confidence']}% confidence."
                )

            elif selected_risk == "High":

                st.warning(
                    f"⚠️ {alert['Priority']} — "
                    f"{alert['Threat']} detected "
                    f"with {alert['Confidence']}% confidence."
                )

            elif selected_risk == "Medium":

                st.info(
                    f"🔎 {alert['Priority']} — "
                    f"{alert['Threat']} detected "
                    f"with {alert['Confidence']}% confidence."
                )

            else:

                st.success(
                    f"🟢 {alert['Priority']} — "
                    f"{alert['Threat']} detected "
                    f"with {alert['Confidence']}% confidence."
                )

            # =================================================
            # SHAP EXPLANATION
            # =================================================

            st.divider()

            st.subheader(
                "🧠 SHAP Feature Explanation"
            )

            try:

                with st.spinner(
                    "Calculating SHAP explanation..."
                ):

                    explainer = shap.TreeExplainer(
                        attack_xgb_model
                    )

                    shap_values = (
                        explainer.shap_values(
                            selected_row
                        )
                    )

                # -------------------------------------
                # Handle different SHAP formats
                # -------------------------------------

                predicted_class_id = int(
                    predictions[
                        selected_index
                    ]
                )

                if isinstance(
                    shap_values,
                    list
                ):

                    class_shap_values = (
                        shap_values[
                            predicted_class_id
                        ][0]
                    )

                elif (
                    isinstance(
                        shap_values,
                        np.ndarray
                    )
                    and shap_values.ndim == 3
                ):

                    # Possible shapes:
                    # samples x features x classes
                    # OR samples x classes x features

                    if (
                        shap_values.shape[2]
                        == len(ATTACK_CLASSES)
                    ):

                        class_shap_values = (
                            shap_values[
                                0,
                                :,
                                predicted_class_id
                            ]
                        )

                    else:

                        class_shap_values = (
                            shap_values[
                                0,
                                predicted_class_id,
                                :
                            ]
                        )

                elif (
                    isinstance(
                        shap_values,
                        np.ndarray
                    )
                    and shap_values.ndim == 2
                ):

                    class_shap_values = (
                        shap_values[0]
                    )

                else:

                    class_shap_values = np.array(
                        shap_values
                    ).reshape(-1)

                # -------------------------------------
                # Create SHAP dataframe
                # -------------------------------------

                shap_df = pd.DataFrame({

                    "Feature":
                        feature_names,

                    "SHAP Value":
                        class_shap_values,

                    "Absolute SHAP":
                        np.abs(
                            class_shap_values
                        ),

                    "Feature Value":
                        selected_row.iloc[0].values

                })

                shap_df = (
                    shap_df
                    .sort_values(
                        "Absolute SHAP",
                        ascending=False
                    )
                    .reset_index(drop=True)
                )

                # -------------------------------------
                # Top positive / negative contributors
                # -------------------------------------

                st.write(
                    f"Top features influencing "
                    f"the prediction: **{selected_prediction}**"
                )

                st.dataframe(
                    shap_df.head(20),
                    use_container_width=True,
                    hide_index=True
                )

                # -------------------------------------
                # SHAP bar chart
                # -------------------------------------

                top_shap = (
                    shap_df
                    .head(15)
                    .sort_values(
                        "Absolute SHAP"
                    )
                )

                fig, ax = plt.subplots(
                    figsize=(10, 7)
                )

                ax.barh(
                    top_shap[
                        "Feature"
                    ],
                    top_shap[
                        "SHAP Value"
                    ]
                )

                ax.set_title(
                    f"Top SHAP Features — "
                    f"{selected_prediction}"
                )

                ax.set_xlabel(
                    "SHAP Value"
                )

                ax.set_ylabel(
                    "Network Feature"
                )

                st.pyplot(
                    fig,
                    use_container_width=True
                )

                plt.close(fig)

                st.info(
                    """
                    SHAP values show how individual
                    network features contribute to the
                    model's prediction. Larger absolute
                    values indicate stronger influence.
                    """
                )

            except Exception as shap_error:

                st.warning(
                    "SHAP explanation could not be generated "
                    "for this model/version."
                )

                st.code(
                    str(shap_error)
                )

        except Exception as e:

            st.error(
                "❌ Error while processing the uploaded CSV."
            )

            st.exception(e)


# ============================================================
# FOOTER
# ============================================================

st.sidebar.markdown("---")

st.sidebar.caption(
    "AI-Driven Security Framework"
)

st.sidebar.caption(
    "Secure Military Information Systems"
)

st.sidebar.caption(
    "XGBoost + SHAP + Risk Scoring"
)