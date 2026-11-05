
import pandas as pd
import os

# Create output folder
os.makedirs("processed_data", exist_ok=True)

# Load datasets
hdfs = pd.read_csv("data/HDFS_2k.log_structured.csv")
swe = pd.read_csv("data/swebench_lite.csv")

# ---------------- HDFS PREPROCESSING ----------------

# Handle missing values
for col in ["Content", "EventTemplate", "Level", "Component"]:
    hdfs[col] = hdfs[col].fillna("")

# Combine log content and template
hdfs["log_text"] = (
    hdfs["Content"] + " " + hdfs["EventTemplate"]
).str.strip()

# Combine date and time
hdfs["timestamp"] = (
    hdfs["Date"].astype(str) + " " + hdfs["Time"].astype(str)
)

# Save processed HDFS data
hdfs.to_csv("processed_data/hdfs_clean.csv", index=False)


# ---------------- SWE-BENCH PREPROCESSING ----------------

# Handle missing text values
for col in ["problem_statement", "hints_text"]:
    swe[col] = swe[col].fillna("")

# Create combined issue description
swe["issue_text"] = (
    swe["problem_statement"] + " " + swe["hints_text"]
).str.strip()

# Save processed SWE-bench data
swe.to_csv("processed_data/swebench_clean.csv", index=False)


# ---------------- RESULTS ----------------

print("\nHDFS PREPROCESSING COMPLETED")
print("Total records:", len(hdfs))
print("Missing values:\n", hdfs.isnull().sum())

print("\nSWE-BENCH PREPROCESSING COMPLETED")
print("Total records:", len(swe))
print("Missing values:\n", swe.isnull().sum())

print("\nProcessed files saved successfully!")
