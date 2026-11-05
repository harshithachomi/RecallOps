
import streamlit as st
import plotly.express as px
import pandas as pd
from src.ai_agent import ask_agent, save_feedback

# Load actual datasets
hdfs_df = pd.read_csv("processed_data/hdfs_clean.csv")
swe_df = pd.read_csv("processed_data/swebench_clean.csv")

# Calculate statistics
total_logs = len(hdfs_df)
warn_logs = (hdfs_df["Level"] == "WARN").sum()
total_issues = len(swe_df)
total_banks = 2

# Repository statistics
repo_counts = swe_df["repo"].value_counts().head(5)

# Log distribution
log_counts = hdfs_df["Level"].value_counts()

# Page configuration
st.set_page_config(
    page_title="CyberIncidentAI",
    page_icon="🛡️",
    layout="wide"
)

# Light blue and white theme with dark text
st.markdown("""
<style>

/* Main background and text */
.stApp {
    background-color: #EAF3FF;
    color: #193D68 !important;
}

/* All headings and text */
.stApp h1,
.stApp h2,
.stApp h3,
.stApp h4,
.stApp p,
.stApp span,
.stApp label,
.stApp li,
.stApp [data-testid="stMarkdownContainer"],
.stApp [data-testid="stMetricLabel"],
.stApp [data-testid="stMetricValue"],
.stApp [data-testid="stMetricDelta"] {
    color: #193D68 !important;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background-color: #DCEBFA;
}

[data-testid="stSidebar"] * {
    color: #193D68 !important;
}

/* Sidebar radio buttons */
[data-testid="stSidebar"] [role="radiogroup"] label {
    color: #193D68 !important;
}

/* Metric cards */
div[data-testid="stMetric"] {
    background-color: #FFFFFF;
    padding: 20px;
    border-radius: 15px;
    border: 1px solid #D5E5F5;
}

/* Information boxes */
[data-testid="stAlert"] {
    background-color: #D6E9FC;
    border-radius: 12px;
}

[data-testid="stAlert"] p {
    color: #193D68 !important;
}

/* Dividers */
hr {
    border-color: #C5D9EE;
}

</style>

/* Dataframe text */
[data-testid="stDataFrame"] * {
    color: #193D68 !important;
}

/* Table text */
[data-testid="stTable"] * {
    color: #193D68 !important;
}

/* Select boxes and input text */
.stSelectbox div,
.stTextInput input {
    color: #193D68 !important;
}

/* General dataframe background */
[data-testid="stDataFrame"] {
    background-color: #FFFFFF;
    border-radius: 12px;
}

/* Subheaders and captions */
.stApp h1,
.stApp h2,
.stApp h3,
.stApp p {
    color: #193D68 !important;
}

""", unsafe_allow_html=True)


# Sidebar navigation
st.sidebar.title("🛡️ CyberIncidentAI")
st.sidebar.caption("AI-powered Intelligence Platform")

page = st.sidebar.radio(
    "NAVIGATION",
    [
        "Dashboard",
        "HDFS Intelligence",
        "SWE-bench Intelligence",
        "AI Agent",
        "Memory & Feedback"
    ]
)

st.sidebar.divider()
st.sidebar.info("Powered by Hindsight AI")


# Main Dashboard
if page == "Dashboard":

    st.title("Welcome to CyberIncidentAI")
    st.caption("AI-powered Security and Software Intelligence")

    st.divider()

    # Statistics cards
    col1, col2, col3, col4 = st.columns(4)

    col1.metric("HDFS Log Records", f"{total_logs:,}")
    col2.metric("WARN Records", f"{warn_logs:,}")
    col3.metric("SWE-bench Issues", f"{total_issues:,}")
    col4.metric("Memory Banks", f"{total_banks:,}")

    st.write("")

    # Charts section
    left, right = st.columns(2)

    # HDFS pie chart
    with left:

        st.subheader("HDFS Log Distribution")

        log_data = pd.DataFrame({
    "Level": log_counts.index,
    "Count": log_counts.values
})

        fig = px.pie(
            log_data,
            names="Level",
            values="Count",
            hole=0.55,
            color="Level",
            color_discrete_map={
                "INFO": "#5B9BD5",
                "WARN": "#F0A35E"
            }
        )

        fig.update_layout(
            template="plotly_white",
            paper_bgcolor="white",
            plot_bgcolor="white",
            font=dict(
                family="Arial",
                size=14,
                color="#193D68"
            ),
            legend=dict(
                font=dict(
                    color="#193D68",
                    size=13
                )
            )
        )

        fig.update_traces(
            textfont=dict(
                color="#193D68",
                size=14
            ),
            textinfo="label+percent"
        )

        st.plotly_chart(fig, use_container_width=True)


    # SWE-bench bar chart
    with right:

        st.subheader("Top SWE-bench Repositories")

        repo_data = pd.DataFrame({
    "Repository": repo_counts.index,
    "Issues": repo_counts.values
})

        fig = px.bar(
            repo_data,
            x="Issues",
            y="Repository",
            orientation="h",
            color="Issues",
            color_continuous_scale="Blues",
            text="Issues"
        )

        fig.update_layout(
            template="plotly_white",
            paper_bgcolor="white",
            plot_bgcolor="white",
            font=dict(
                family="Arial",
                size=14,
                color="#193D68"
            ),
            xaxis=dict(
                title="Number of Issues",
                tickfont=dict(color="#193D68"),
                title_font=dict(color="#193D68"),
                gridcolor="#E3EDF7"
            ),
            yaxis=dict(
                title="Repository",
                tickfont=dict(color="#193D68"),
                title_font=dict(color="#193D68"),
                categoryorder="total ascending"
            ),
            coloraxis_showscale=False
        )

        fig.update_traces(
            textposition="outside",
            textfont=dict(
                color="#193D68",
                size=13
            )
        )

        st.plotly_chart(fig, use_container_width=True)


    st.divider()

    # Intelligence modules
    st.subheader("Intelligence Modules")

    col1, col2, col3 = st.columns(3)

    col1.info(
        "📁 HDFS Intelligence\n\n"
        "Analyze log patterns and rare events."
    )

    col2.info(
        "💻 SWE-bench Intelligence\n\n"
        "Explore software issues and repositories."
    )

    col3.info(
        "🧠 Hindsight AI Agent\n\n"
        "Recall previous findings and feedback."
    )


# HDFS page
# HDFS page
elif page == "HDFS Intelligence":

    st.title("HDFS Log Intelligence")
    st.caption("Analyze Hadoop Distributed File System logs")

    st.divider()

    # HDFS statistics
    col1, col2, col3 = st.columns(3)

    col1.metric("Total Log Records", f"{len(hdfs_df):,}")
    col2.metric("INFO Records", f"{(hdfs_df['Level'] == 'INFO').sum():,}")
    col3.metric("WARN Records", f"{(hdfs_df['Level'] == 'WARN').sum():,}")

    st.divider()

    # Component analysis
    st.subheader("Top HDFS Components")

    component_counts = hdfs_df["Component"].value_counts().head(10)

    component_data = pd.DataFrame({
        "Component": component_counts.index,
        "Count": component_counts.values
    })

    fig = px.bar(
        component_data,
        x="Count",
        y="Component",
        orientation="h",
        text="Count",
        color="Count",
        color_continuous_scale="Blues"
    )

    fig.update_layout(
        template="plotly_white",
        paper_bgcolor="white",
        plot_bgcolor="white",
        font=dict(color="#193D68"),
        yaxis=dict(categoryorder="total ascending")
    )

    st.plotly_chart(fig, use_container_width=True)

    st.divider()

        # Rare event analysis
    st.divider()

    st.subheader("Rare HDFS Events")

    event_counts = hdfs_df["EventTemplate"].value_counts()

    rare_events = event_counts[event_counts <= 2]

    st.metric("Rare Event Types", len(rare_events))

    if len(rare_events) > 0:

        rare_data = pd.DataFrame({
            "Event Template": rare_events.index,
            "Occurrences": rare_events.values
        })

        st.dataframe(
            rare_data,
            use_container_width=True,
            hide_index=True
        )

    else:
        st.success("No rare events found.")

    # HDFS log records
    st.subheader("HDFS Log Records")

    st.dataframe(
        hdfs_df[["Date", "Time", "Level", "Component", "Content"]],
        use_container_width=True,
        hide_index=True
    )


# SWE-bench page
# SWE-bench page
elif page == "SWE-bench Intelligence":

    st.title("SWE-bench Intelligence")
    st.caption("Explore software issues and repository statistics")

    st.divider()

    # Basic statistics
    col1, col2, col3 = st.columns(3)

    col1.metric("Total Issues", f"{len(swe_df):,}")
    col2.metric("Repositories", f"{swe_df['repo'].nunique():,}")
    col3.metric(
        "Unspecified Difficulty",
        f"{swe_df['difficulty'].isna().sum():,}"
    )

    st.divider()

    # Repository analysis
    st.subheader("Top 10 Repositories")

    repo_stats = swe_df["repo"].value_counts().head(10)

    repo_data = pd.DataFrame({
        "Repository": repo_stats.index,
        "Issues": repo_stats.values
    })

    fig = px.bar(
        repo_data,
        x="Issues",
        y="Repository",
        orientation="h",
        text="Issues",
        color="Issues",
        color_continuous_scale="Blues"
    )

    fig.update_layout(
        template="plotly_white",
        paper_bgcolor="white",
        plot_bgcolor="white",
        font=dict(color="#193D68", size=13),
        xaxis=dict(title="Number of Issues"),
        yaxis=dict(
            title="Repository",
            categoryorder="total ascending"
        ),
        coloraxis_showscale=False
    )

    st.plotly_chart(fig, use_container_width=True)

    st.divider()

    # Difficulty analysis
    st.subheader("Issue Difficulty Distribution")

    difficulty_counts = (
        swe_df["difficulty"]
        .fillna("Not specified")
        .value_counts()
    )

    difficulty_data = pd.DataFrame({
        "Difficulty": difficulty_counts.index,
        "Issues": difficulty_counts.values
    })

    fig = px.pie(
        difficulty_data,
        names="Difficulty",
        values="Issues",
        hole=0.45
    )

    fig.update_layout(
        template="plotly_white",
        paper_bgcolor="white",
        font=dict(color="#193D68", size=13)
    )

    fig.update_traces(
        textfont=dict(color="#193D68"),
        textinfo="label+percent"
    )

    st.plotly_chart(fig, use_container_width=True)

    st.divider()

    # Issue records
    st.subheader("Software Issue Records")

    st.dataframe(
        swe_df[["repo", "instance_id", "difficulty", "created_at"]],
        use_container_width=True,
        hide_index=True
    )


# AI Agent page

# AI Agent page
elif page == "AI Agent":

    st.title("CyberIncidentAI Agent")
    st.caption("Ask questions using Hindsight persistent memory")

    st.divider()

    domain_choice = st.selectbox(
        "Select Intelligence Domain",
        ["HDFS Log Intelligence", "SWE-bench Intelligence"]
    )

    domain = "hdfs" if domain_choice == "HDFS Log Intelligence" else "swe"

    question = st.text_area(
        "Enter your question",
        placeholder="Ask a question about your dataset..."
    )

    if st.button("Ask AI Agent", type="primary"):

        if question.strip():

            with st.spinner("AI Agent is processing your question..."):

                result = ask_agent(domain, question)

                st.session_state["agent_result"] = result
                st.session_state["agent_question"] = question
                st.session_state["agent_domain"] = domain
                st.session_state["feedback_saved"] = False

        else:
            st.warning("Please enter a question.")

    if "agent_result" in st.session_state:

        result = st.session_state["agent_result"]

        st.divider()

        if "error" in result:

            st.error(result["error"])

        else:

            st.subheader("Previous Memories")

            if result["memories"]:
                for memory in result["memories"]:
                    st.info(memory)
            else:
                st.write("No previous memories found.")

            st.subheader("AI Agent Response")
            st.markdown(result["answer"])

            st.divider()

            st.subheader("Was this response useful?")

            col1, col2 = st.columns(2)

            with col1:
                if st.button("Yes, Useful"):

                    saved = save_feedback(
                        st.session_state["agent_domain"],
                        st.session_state["agent_question"],
                        True
                    )

                    if saved:
                        st.session_state["feedback_saved"] = True
                        st.success("Feedback saved in Hindsight!")
                    else:
                        st.error("Could not save feedback.")

            with col2:
                if st.button("No, Improve"):
                    st.session_state["show_reason"] = True

            if st.session_state.get("show_reason", False):

                reason = st.text_input(
                    "What should be improved?"
                )

                if st.button("Submit Feedback"):

                    saved = save_feedback(
                        st.session_state["agent_domain"],
                        st.session_state["agent_question"],
                        False,
                        reason
                    )

                    if saved:
                        st.session_state["feedback_saved"] = True
                        st.session_state["show_reason"] = False
                        st.success("Improvement feedback saved!")
                    else:
                        st.error("Could not save feedback.")


# Memory page
# Memory & Feedback page
elif page == "Memory & Feedback":

    st.title("Memory & Feedback")
    st.caption("Explore information stored by the Hindsight memory system.")

    st.divider()

    st.subheader("Persistent Memory Banks")

    col1, col2 = st.columns(2)

    with col1:
        st.info("HDFS Intelligence")
        st.write("Bank ID: hdfs-intelligence")

    with col2:
        st.info("SWE-bench Intelligence")
        st.write("Bank ID: swebench-intelligence")

    st.divider()

    st.subheader("Search Previous Memories")

    domain_choice = st.selectbox(
        "Select Memory Domain",
        ["HDFS Intelligence", "SWE-bench Intelligence"]
    )

    domain = "hdfs" if domain_choice == "HDFS Intelligence" else "swe"

    memory_question = st.text_input(
        "What memory would you like to retrieve?",
        placeholder="Example: What limitations were found previously?"
    )

    if st.button("Retrieve Memories", type="primary"):

        if memory_question.strip():

            with st.spinner("Retrieving information from Hindsight..."):

                result = ask_agent(domain, memory_question)

            if "error" in result:
                st.error(result["error"])

            else:
                st.subheader("Retrieved Memories")

                if result["memories"]:
                    for memory in result["memories"]:
                        st.success(memory)
                else:
                    st.info("No related memories found.")

        else:
            st.warning("Please enter a search question.")

    st.divider()

    st.subheader("How Memory Works")

    st.write("""
    1. The AI Agent stores important findings in Hindsight.
    2. Previous information is retained in persistent memory banks.
    3. Hindsight retrieves relevant information for new questions.
    4. User feedback is stored to help guide future responses.
    """)