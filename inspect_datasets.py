import os
import pandas as pd

hdfs_path = os.path.join("data", "HDFS_2k.log_structured.csv")
swe_path = os.path.join("data", "swebench_lite.csv")

print("HDFS exists:", os.path.exists(hdfs_path))
print("SWE exists:", os.path.exists(swe_path))

hdfs = pd.read_csv(hdfs_path)
swe = pd.read_csv(swe_path)

print("HDFS Shape:", hdfs.shape)
print("HDFS Columns:", hdfs.columns.tolist())

print("SWE Shape:", swe.shape)
print("SWE Columns:", swe.columns.tolist())