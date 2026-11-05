
import pandas as pd
import os
from hindsight_memory import remember_and_recall

# Load processed HDFS dataset
df = pd.read_csv("processed_data/hdfs_clean.csv")

# Create output folder
os.makedirs("reports", exist_ok=True)

print("\n========== HDFS LOG ANALYSIS ==========")

# 1. Total log records
total_logs = len(df)
print("\nTotal Logs:", total_logs)

# 2. Log level distribution
levels = df["Level"].value_counts()
print("\nLog Level Distribution:")
print(levels)

# 3. Component distribution
components = df["Component"].value_counts().head(10)
print("\nTop Components:")
print(components)

# 4. Most frequent event templates
events = df["EventTemplate"].value_counts()
print("\nTop Event Templates:")
print(events.head(10))

# 5. Find rare event templates
rare_events = events[events <= 2]
print("\nRare Event Templates:")
print(rare_events)

# 6. Save analysis results
rare_events.to_csv("reports/rare_hdfs_events.csv")
levels.to_csv("reports/log_level_distribution.csv")
events.to_csv("reports/event_frequency.csv")

# 7. Prepare findings for Hindsight
findings = f"""
HDFS Analysis Results:
Total logs: {total_logs}

Log level distribution:
{levels.to_string()}

Top components:
{components.to_string()}

Top event templates:
{events.head(10).to_string()}

Rare event templates:
{rare_events.to_string()}

Note: Rare events are candidates for investigation,
not confirmed anomalies.
"""

# 8. Store and recall memories
memories = remember_and_recall(
    bank_id="hdfs-intelligence",
    content=findings,
    query="What previous HDFS log patterns and findings were identified?"
)

print("\n========== PREVIOUS HDFS MEMORIES ==========")

for memory in memories:
    print("\n", memory)

print("\nHDFS Analysis Completed!")
print("Reports saved in reports folder.")
