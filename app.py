import sys
sys.path.append('G:\\Project\\phishing-detection')
from phishingdetection import FeatureExtraction
import numpy as np
from phishingdetection import gbc  # Ensure gbc is defined in your phishingdetection module
import streamlit as st

st.title("Phishing Website Detection")

# User input for URL
url = st.text_input("Enter the URL:", key="url_input")

# Predict and display the result
if st.button("Check"):
    if url:
        # Initialize the FeatureExtraction object with the input URL
        obj = FeatureExtraction(url)
        
        # Extract features as a numpy array and reshape it
        features = np.array(obj.getFeaturesList()).reshape(1, -1)  # Reshape to (1, num_features)
        
        # Predict using the trained GradientBoostingClassifier
        y_pred = gbc.predict(features)[0]  # Ensure gbc is already trained
        
        # Display the result based on prediction
        if y_pred == 1:
            st.write("We guess it is a safe website.")
        else:
            st.write("Caution! Suspicious website detected.")
        
        # Display the prediction result
        st.write(f"Prediction: {y_pred}")
    else:
        st.write("Please enter a URL.")