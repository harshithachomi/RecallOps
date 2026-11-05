import os
from dotenv import load_dotenv
from hindsight_client import Hindsight

load_dotenv()

client = Hindsight(
    base_url=os.getenv("HINDSIGHT_API_URL"),
    api_key=os.getenv("HINDSIGHT_API_KEY")
)

try:
    # Create SWE-bench memory bank
    client.create_bank(
        bank_id="swebench-intelligence",
        name="SWE-bench Intelligence"
    )

    print("SWE-bench memory bank created!")

    # Store dataset findings
    client.retain(
        bank_id="swebench-intelligence",
        content="""
        SWE-bench Lite dataset analysis:
        Total software issues analyzed: 300.

        Top repositories:
        django/django: 114 issues
        sympy/sympy: 77 issues
        matplotlib/matplotlib: 23 issues
        scikit-learn/scikit-learn: 23 issues.

        Difficulty information:
        207 records have missing difficulty labels.
        45 records are classified as 15 minutes to 1 hour.
        45 records are classified as less than 15 minutes.
        3 records are classified as 1 to 4 hours.

        Similarity-based retrieval needs improvement because
        the initial test query returned low similarity scores.
        """

    )

    print("SWE-bench findings stored successfully!")

    # Recall stored findings
    result = client.recall(
        bank_id="swebench-intelligence",
        query="Which repository has the most issues?"
    )

    print("\nRecalled memories:")

    for memory in result.results:
        print(memory.text)

finally:
    client.close()