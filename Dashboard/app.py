import streamlit as st
import pandas as pd

st.title("SentinelAI Cyber Defense Dashboard")

data = pd.read_csv("data/sample_logs.csv")

st.write("Network Activity")

st.dataframe(data)

threats = data[data['failed_login'] > 10]

st.write("Detected Threats")

st.dataframe(threats)