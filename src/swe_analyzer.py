
import pandas as pd
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from hindsight_memory import remember_and_recall

# Load dataset
df = pd.read_csv("processed_data/swebench_clean.csv")

df["issue_text"] = df["issue_text"].fillna("")
df = df[df["issue_text"].str.strip() != ""].copy()

print("\n========== SWE-BENCH ANALYSIS ==========")

# Dataset information
total_issues = len(df)
print("Total Issues:", total_issues)

top_repos = df["repo"].value_counts().head(10)
print("\nTop Repositories:")
print(top_repos)

difficulty = df["difficulty"].value_counts(dropna=False)
print("\nDifficulty Distribution:")
print(difficulty)

# TF-IDF similarity analysis
vectorizer = TfidfVectorizer(
    stop_words="english",
    max_features=5000
)

tfidf_matrix = vectorizer.fit_transform(df["issue_text"])

query = input("\nEnter a software issue: ")

query_vector = vectorizer.transform([query])

similarity = cosine_similarity(
    query_vector, tfidf_matrix
).flatten()

# Get top 5 similar issues
top_indices = similarity.argsort()[-5:][::-1]

results = df.iloc[top_indices].copy()
results["similarity_score"] = similarity[top_indices]

print("\nTop 5 Similar Issues:")

for _, row in results.iterrows():
    print("\nInstance ID:", row["instance_id"])
    print("Repository:", row["repo"])
    print("Difficulty:", row["difficulty"])
    print("Similarity:", round(row["similarity_score"], 3))
    print("Problem:", row["problem_statement"][:300])
    print("Available Patch:", pd.notna(row["patch"]) and bool(str(row["patch"]).strip()))

# Save results
os.makedirs("reports", exist_ok=True)

results.to_csv(
    "reports/similar_swe_issues.csv",
    index=False
)

# Prepare findings for Hindsight
findings = f"""
SWE-bench Analysis Results:

Total issues: {total_issues}

Top repositories:
{top_repos.to_string()}

Difficulty distribution:
{difficulty.to_string()}

User search query:
{query}

Top 5 similar issues:
{results[['instance_id', 'repo', 'difficulty', 'similarity_score']].to_string(index=False)}

Retrieval note:
Similarity scores must be evaluated before treating
retrieved issues as relevant examples.
"""

# Store and recall memories
memories = remember_and_recall(
    bank_id="swebench-intelligence",
    content=findings,
    query=f"What previous software issues and findings are relevant to: {query}?"
)

print("\n========== PREVIOUS SWE-BENCH MEMORIES ==========")

for memory in memories:
    print("\n", memory)

print("\nSWE-bench Analysis Completed!")
print("Results saved in reports/similar_swe_issues.csv")
