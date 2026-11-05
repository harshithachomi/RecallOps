
import os
from dotenv import load_dotenv
from hindsight_client import Hindsight

load_dotenv()

client = Hindsight(
    base_url=os.getenv("HINDSIGHT_API_URL"),
    api_key=os.getenv("HINDSIGHT_API_KEY")
)

BANKS = {
    "hdfs": "hdfs-intelligence",
    "swe": "swebench-intelligence"
}


# Main function used by the Streamlit dashboard
def ask_agent(domain, question):

    if domain not in BANKS:
        return {"error": "Invalid domain"}

    bank_id = BANKS[domain]

    try:
        memories = client.recall(
            bank_id=bank_id,
            query=question
        )

        previous_memories = []

        if memories.results:
            previous_memories = [
                memory.text for memory in memories.results
            ]

        response = client.reflect(
            bank_id=bank_id,
            query=f"""
            Answer the following question: {question}

            Consider previous user feedback stored in memory.
            Improve the response based on that feedback.
            Be accurate and mention limitations when necessary.
            """,
            budget="mid"
        )

        return {
            "answer": response.text,
            "memories": previous_memories
        }

    except Exception as e:
        return {"error": str(e)}


# Store feedback in Hindsight
def save_feedback(domain, question, useful, reason=""):

    if domain not in BANKS:
        return False

    feedback_note = (
        f"User feedback: The response was "
        f"{'useful' if useful else 'not useful'}. "
        f"Question: {question}. "
        f"Reason: {reason if reason else 'Not specified'}"
    )

    try:
        client.retain(
            bank_id=BANKS[domain],
            content=feedback_note
        )
        return True

    except Exception:
        return False


# Original PowerShell functionality
def run_agent(domain, question):

    result = ask_agent(domain, question)

    if "error" in result:
        print("Agent Error:", result["error"])
        return

    print("\nPrevious Memories:")

    for memory in result["memories"]:
        print("-", memory)

    print("\n========== AI AGENT RESPONSE ==========")
    print(result["answer"])

    feedback = input("\nWas this response useful? (yes/no): ").strip().lower()

    if feedback in ["yes", "y"]:
        save_feedback(domain, question, True)
        print("Feedback stored!")

    elif feedback in ["no", "n"]:
        reason = input("What should be improved? ").strip()
        save_feedback(domain, question, False, reason)
        print("Feedback stored!")


if __name__ == "__main__":

    print("1. HDFS Log Intelligence")
    print("2. SWE-bench Intelligence")

    choice = input("\nSelect domain (1 or 2): ")
    question = input("\nEnter your question: ")

    if choice == "1":
        run_agent("hdfs", question)

    elif choice == "2":
        run_agent("swe", question)

    else:
        print("Invalid choice!")

    client.close()
