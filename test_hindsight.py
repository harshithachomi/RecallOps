import os
from dotenv import load_dotenv
from hindsight_client import Hindsight

# Load API credentials
load_dotenv()

api_url = os.getenv("HINDSIGHT_API_URL")
api_key = os.getenv("HINDSIGHT_API_KEY")

if not api_url or not api_key:
    raise ValueError("Hindsight credentials are missing!")

# Connect to Hindsight
client = Hindsight(
    base_url=api_url,
    api_key=api_key
)

try:
    # Create a memory bank
    client.create_bank(
        bank_id="hdfs-intelligence",
        name="HDFS Intelligence"
    )

    print("Memory bank created!")

    # Store a test memory
    client.retain(
        bank_id="hdfs-intelligence",
        content="Our HDFS dataset contains 2000 log records, including 1920 INFO records and 80 WARN records."
    )

    print("Memory stored successfully!")

    # Retrieve the memory
    result = client.recall(
        bank_id="hdfs-intelligence",
        query="How many WARN records were found?"
    )

    print("\nRecalled memories:")
    for memory in result.results:
        print(memory.text)

finally:
    client.close()