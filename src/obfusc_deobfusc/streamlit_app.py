import streamlit as st
import tempfile
import io
import contextlib
import re

from tools.format_detector import detect_code_format, is_obfuscated
from crew import agents
from crewai import Task, Crew

# Capture stdout logs from LLM execution
def capture_logs(func, *args, **kwargs):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        result = func(*args, **kwargs)
    logs = buf.getvalue()
    return result, logs

# Extract code from markdown-style ``` blocks
def extract_code_block(text):
    match = re.search(r"```(?:python|js)?\n(.*?)```", text, re.DOTALL)
    return match.group(1).strip() if match else text.strip()

# App layout and title
st.set_page_config(page_title="Code Obfuscator / Deobfuscator", layout="wide")
st.title("💻 Code Obfuscator / Deobfuscator")

uploaded_file = st.file_uploader("Upload your Python or JavaScript file", type=["py", "js"])

if uploaded_file:
    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=uploaded_file.name) as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = tmp.name

    uploaded_file.seek(0)
    code = uploaded_file.read().decode("utf-8")

    lang = detect_code_format(tmp_path)
    obfuscated = is_obfuscated(code)

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📥 Original Code")
        st.code(code, language=lang)

    with col2:
        st.markdown(f"🧠 **Detected Language**: `{lang}`")
        st.markdown(f"🔍 **Code is Obfuscated?** `{obfuscated}`")

    # Build transformation task
    action = "deobfuscate" if obfuscated else "obfuscate"
    agent_key = "obfuscation_agent" if action == "obfuscate" else "deobfuscation_agent"

    task = Task(
        description=f"{action.capitalize()} the following {lang} code:\n\n{code}",
        expected_output="Return only the final transformed code inside a code block. No explanations.",
        agent=agents[agent_key]
    )

    if st.button(f"Run Agent to {action.capitalize()}"):
        # Mini Crew for transformation
        crew = Crew(
            agents=[task.agent],
            tasks=[task],
            verbose=True
        )

        raw_output, agent_logs = capture_logs(crew.kickoff)
        transformed_code = extract_code_block(str(raw_output))
        
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("📤 Transformed Code")
            st.code(transformed_code, language=lang)

        with col2:
            with st.expander("🤖 Obfuscator/Deobfuscator Agent logs"):
                st.markdown(f"```\n{agent_logs}\n```")


        # Verifier task to compare functionality
        verify_task = Task(
            description=f"Check if the following two versions of code behave the same.\n\nOriginal Code:\n{code}\n\n{action.capitalize()}d Code:\n{transformed_code}",
            expected_output="Clearly state whether both versions produce the same result.",
            agent=agents["verifier_agent"]
        )

        verifier_crew = Crew(
            agents=[verify_task.agent],
            tasks=[verify_task],
            verbose=True
        )

        verify_result, verify_logs = capture_logs(verifier_crew.kickoff)
        verify_result = str(verify_result)

        col1, col2 = st.columns(2)

        with col1:
            st.subheader("✅ Verification Result")
            st.code(verify_result)

        with col2:
            with st.expander("🤖 Verifier Agent Logs"):
                st.markdown(f"```\n{verify_logs}\n```")

        st.download_button(
            "💾 Download Transformed",
            data=transformed_code,
            file_name=f"{action}ed_code.{lang}",
            mime="text/plain"
        )
