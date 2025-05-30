import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os
import tempfile
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import seaborn as sns
import lief
import traceback
from sklearn.metrics import confusion_matrix, roc_curve, auc, precision_recall_curve
from app import extract_pe_features

# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load and analyze model results
@st.cache_data
def load_model_analysis():
    # Load model and metadata
    logger.debug("Loading model and metadata...")
    model_info = joblib.load('random_forest_model.joblib')
    model = model_info['model']
    optimal_threshold = model_info['optimal_threshold']
    feature_names = model_info['feature_names']
    scaler = model_info['scaler']
    return {
        'model': model,
        'optimal_threshold': optimal_threshold,
        'feature_names': feature_names,
        'scaler': scaler
    }

# Set page configuration
st.set_page_config(
    page_title="Malware File Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load model analysis
analysis_results = load_model_analysis()
model = analysis_results['model']
optimal_threshold = analysis_results['optimal_threshold']
feature_names = analysis_results['feature_names']
scaler = analysis_results['scaler']



# Main title
st.markdown("<h1 style='text-align: center; color: #2c3e50;'>🛡️ Malware File Scanner</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; font-size: 1.2em; color: #7f8c8d;'>Upload a file to scan for malware</p>", unsafe_allow_html=True)

uploaded_file = st.file_uploader("Choose a PE file for analysis", type=["exe", "dll"])

if uploaded_file:
    with st.spinner("Analyzing file..."):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp_file:
            tmp_file.write(uploaded_file.getvalue())
            file_path = tmp_file.name

        try:
            # Extract features using our custom function
            logger.debug(f"Extracting features from file: {file_path}")
            features_df = extract_pe_features(file_path)
            logger.debug(f"Features extracted: {features_df.shape[0]} samples")
            logger.debug(f"Feature names: {list(features_df.columns)}")
            
            # Scale features
            features_scaled = scaler.transform(features_df)
            logger.debug(f"Features scaled. Shape: {features_scaled.shape}")
              # Get prediction and probability
            probability = model.predict_proba(features_scaled)[0][1]
            prediction = int(probability >= optimal_threshold)
            logger.debug(f"Raw probability: {probability:.4f}, Threshold: {optimal_threshold}")
            logger.debug(f"Final prediction: {prediction}")
              # Display result with more detail
            result_color = "#dc3545" if prediction == 1 else "#198754"
            result_text = "⚠️ MALWARE " if prediction == 1 else "✅ BENIGN "
              # Show simple result card
            st.markdown(f"""
                <div class='result-card' style='background-color: {result_color};'>
                    <h2>{result_text}</h2>
                </div>
            """, unsafe_allow_html=True)
            
        except Exception as e:
            st.error(f"Error analyzing file: {str(e)}")
            logger.error(f"Error analyzing file {file_path}: {str(e)}", exc_info=True)
        finally:
            os.unlink(file_path)

