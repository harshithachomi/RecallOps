
import os
from dotenv import load_dotenv
from hindsight_client import Hindsight


def remember_and_recall(bank_id, content, query):

    load_dotenv()

    api_url = os.getenv("HINDSIGHT_API_URL")
    api_key = os.getenv("HINDSIGHT_API_KEY")

    if not api_url or not api_key:
        print("Hindsight credentials missing!")
        return []

    client = Hindsight(
        base_url=api_url,
        api_key=api_key
    )

    try:
        # Store new analysis
        client.retain(
            bank_id=bank_id,
            content=content
        )

        print("\nNew findings stored in Hindsight!")

        # Recall previous knowledge
        result = client.recall(
            bank_id=bank_id,
            query=query
        )

        print("\nPrevious memories recalled!")

        return [memory.text for memory in result.results]

    finally:
        client.close()
