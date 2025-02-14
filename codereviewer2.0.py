import streamlit as st
import requests
import google.generativeai as genai
import subprocess
from streamlit_ace import st_ace
import uuid
from datetime import datetime
import sqlite3
import hashlib
import os

key = os.getenv("GEMINI_API_KEY")  # Retrieve from environment variable

if not key:
    st.error("Gemini API key not found. Please set GEMINI_API_KEY as an environment variable.")
    st.stop()

# Database setup
def init_db():
    conn = sqlite3.connect('code_review.db', check_same_thread=False)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS reviews
                 (id TEXT PRIMARY KEY,
                  username TEXT,
                  code TEXT,
                  review_output TEXT,
                  run_output TEXT,
                  fixed_code TEXT,
                  timestamp TEXT,
                  FOREIGN KEY (username) REFERENCES users(username))''')
    conn.commit()
    conn.close()

# User authentication functions
def hash_password(password):
    salt = "anthropic_secure_salt"
    return hashlib.sha256((password + salt).encode()).hexdigest()

def authenticate(username, password):
    conn = sqlite3.connect('code_review.db', check_same_thread=False)
    c = conn.cursor()
    c.execute('SELECT password FROM users WHERE username=?', (username,))
    result = c.fetchone()
    conn.close()
    return result and result[0] == hash_password(password)

def register_user(username, password):
    if not username or not password:
        return False
    conn = sqlite3.connect('code_review.db', check_same_thread=False)
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users VALUES (?, ?)', 
                 (username, hash_password(password)))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

# Database operations for reviews
def load_user_reviews(username):
    conn = sqlite3.connect('code_review.db', check_same_thread=False)
    c = conn.cursor()
    c.execute('''SELECT id, code, review_output, run_output, fixed_code, timestamp 
                 FROM reviews WHERE username=? ORDER BY timestamp DESC''', (username,))
    reviews = c.fetchall()
    conn.close()
    
    tabs = {}
    for review in reviews:
        tabs[review[0]] = {
            "code": review[1],
            "review_output": review[2],
            "run_output": review[3],
            "fixed_code": review[4],
            "timestamp": review[5],
            "editor_key": 0
        }
    return tabs

def save_review(username, tab_id, tab_data):
    if not username:  # Don't save if user is not logged in
        return
    conn = sqlite3.connect('code_review.db', check_same_thread=False)
    c = conn.cursor()
    c.execute('''INSERT OR REPLACE INTO reviews 
                 VALUES (?, ?, ?, ?, ?, ?, ?)''',
              (tab_id, username, tab_data["code"], 
               tab_data["review_output"], tab_data["run_output"],
               tab_data["fixed_code"], tab_data["timestamp"]))
    conn.commit()
    conn.close()

def run_code(code, tab_id):
    """Execute Python code and capture output."""
    try:
        # Create a temporary file to execute the code
        temp_file = f"temp_{tab_id}.py"
        with open(temp_file, "w") as f:
            f.write(code)
        
        # Run the code and capture output
        result = subprocess.run(
            ["python3", temp_file],
            capture_output=True,
            text=True,
            timeout=30  # 30 second timeout
        )
        
        # Clean up temp file
        os.remove(temp_file)
        
        # Return both stdout and stderr
        output = result.stdout
        if result.stderr:
            output += "\nErrors:\n" + result.stderr
        
        return output
    except subprocess.TimeoutExpired:
        return "Error: Code execution timed out (30 second limit)"
    except Exception as e:
        return f"Error: {str(e)}"
    finally:
        # Ensure temp file is removed even if there's an error
        if os.path.exists(temp_file):
            os.remove(temp_file)

# Initialize session state
def init_session_state():
    if "tabs" not in st.session_state:
        new_tab_id = str(uuid.uuid4())
        st.session_state["tabs"] = {
            new_tab_id: {
                "code": "",
                "review_output": "",
                "run_output": "",
                "fixed_code": "",
                "editor_key": 0,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        }
        st.session_state["current_tab"] = new_tab_id
    
    if 'username' not in st.session_state:
        st.session_state['username'] = None

# Core application functions
def review_code(code, tab_id):
    """Send code to Gemini AI for review and store response."""
    try:
        prompt = f"Review this code and provide fixes:\n{code}"
        response = model.generate_content(prompt)
        st.session_state["tabs"][tab_id]["review_output"] = response.text

        if "```python" in response.text:
            fixed_code = response.text.split("```python")[1].split("```")[0].strip()
            if fixed_code:
                st.session_state["tabs"][tab_id]["fixed_code"] = fixed_code
        
        if st.session_state.get('username'):
            save_review(st.session_state['username'], tab_id, st.session_state["tabs"][tab_id])
    except Exception as e:
        st.error(f"Error during code review: {str(e)}")

def create_new_tab():
    new_tab_id = str(uuid.uuid4())
    st.session_state["current_tab"] = new_tab_id
    st.session_state["tabs"][new_tab_id] = {
        "code": "",
        "review_output": "",
        "run_output": "",
        "fixed_code": "",
        "editor_key": 0,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    if st.session_state.get('username'):
        save_review(st.session_state['username'], new_tab_id, st.session_state["tabs"][new_tab_id])

def delete_tab(tab_id):
    if tab_id in st.session_state["tabs"]:
        if tab_id == st.session_state["current_tab"]:
            remaining_tabs = [t for t in st.session_state["tabs"].keys() if t != tab_id]
            if remaining_tabs:
                st.session_state["current_tab"] = remaining_tabs[0]
            else:
                create_new_tab()
        
        if st.session_state.get('username'):
            conn = sqlite3.connect('code_review.db', check_same_thread=False)
            c = conn.cursor()
            c.execute('DELETE FROM reviews WHERE id=?', (tab_id,))
            conn.commit()
            conn.close()
        
        del st.session_state["tabs"][tab_id]

def apply_fixed_code(tab_id):
    if st.session_state["tabs"][tab_id]["fixed_code"]:
        st.session_state["tabs"][tab_id]["code"] = st.session_state["tabs"][tab_id]["fixed_code"]
        st.session_state["tabs"][tab_id]["editor_key"] += 1
        if st.session_state.get('username'):
            save_review(st.session_state['username'], tab_id, st.session_state["tabs"][tab_id])

def get_sorted_tabs():
    return dict(sorted(
        st.session_state["tabs"].items(),
        key=lambda x: x[1]['timestamp'],
        reverse=True
    ))

# Initialize application
init_db()
init_session_state()

# Load Gemini API key and configure model
try:
    with open(".gemini.txt", "r") as file:
        key = file.read().strip()
except FileNotFoundError:
    st.error("Gemini API key not found. Please create .gemini.txt file with your API key.")
    st.stop()

# System prompt for Gemini
system_prompt = """You are a code reviewer specializing in Python. Your task is to:
- Analyze submitted code.
- Identify potential bugs or errors.
- Suggest optimizations or improvements.
- Provide the corrected version in Python if the code is in another language.

🔍 **Response Structure**:
1️⃣ **Bug/Error Identification**
   - Detect errors in the provided code.
   - If it's **not Python**, identify the language and explain syntax differences.
   
2️⃣ **Suggested Fixes/Optimizations**
   - Recommend fixes for errors.
   - If the code is in another language, show the **correct equivalent in Python**.

3️⃣ **Corrected Code**
   - Provide the correct **Python version**.
   - Ensure it's fully functional and valid.
   - Explain the changes.

📌 **Important**:
- If the code is in Java, C++, JavaScript, etc., explain how to translate it into Python.
- DO NOT reject non-Python code; instead, analyze it and convert it if possible.
- Always wrap the corrected Python code in triple backticks with 'python' language identifier.
"""

genai.configure(api_key=key)
model = genai.GenerativeModel("gemini-2.0-flash-exp", system_instruction=system_prompt)

# Sidebar
with st.sidebar:
    st.title("Code Review History")
    
    # Login/Register/Logout section
    if not st.session_state.get('username'):
        with st.expander("Login/Register (Optional)"):
            tab1, tab2 = st.tabs(["Login", "Register"])
            
            with tab1:
                username = st.text_input("Username", key="login_username")
                password = st.text_input("Password", type="password", key="login_password")
                if st.button("Login"):
                    if authenticate(username, password):
                        st.session_state['username'] = username
                        st.session_state["tabs"] = load_user_reviews(username)
                        if not st.session_state["tabs"]:
                            create_new_tab()
                        st.rerun()
                    else:
                        st.error("Invalid username or password")

            with tab2:
                new_username = st.text_input("Username", key="reg_username")
                new_password = st.text_input("Password", type="password", key="reg_password")
                if st.button("Register"):
                    if register_user(new_username, new_password):
                        st.success("Registration successful! Please login.")
                    else:
                        st.error("Username already exists or invalid input")
    else:
        st.write(f"Logged in as: {st.session_state['username']}")
        if st.button("Logout"):
            st.session_state['username'] = None
            st.session_state["tabs"] = {}  # Clear tabs on logout
            st.rerun()
    
    if st.button("New Review", type="primary"):
        create_new_tab()
        st.rerun()
    
    st.divider()
    
    # Display history
    sorted_tabs = get_sorted_tabs()
    for tab_id, tab_data in sorted_tabs.items():
        col1, col2 = st.columns([4, 1])
        with col1:
            if st.button(
                f"Review from {tab_data['timestamp']}",
                key=f"history_{tab_id}",
                use_container_width=True
            ):
                st.session_state["current_tab"] = tab_id
                st.rerun()
        with col2:
            if st.button("🗑️", key=f"delete_{tab_id}"):
                delete_tab(tab_id)
                st.rerun()

    # File upload section
    st.divider()
    uploaded_file = st.file_uploader("Upload a Python file", type=["py"])
    if uploaded_file is not None:
        # Read the content of the uploaded file
        code = uploaded_file.read().decode("utf-8")
        # Set the code in the current tab
        st.session_state["tabs"][st.session_state["current_tab"]]["code"] = code
        st.session_state["tabs"][st.session_state["current_tab"]]["editor_key"] += 1
        if st.session_state.get('username'):
            save_review(st.session_state['username'], st.session_state["current_tab"], st.session_state["tabs"][st.session_state["current_tab"]])

# Main content area
if "tabs" in st.session_state and st.session_state["tabs"]:
    current_tab = st.session_state.get("current_tab", None)
    
    if current_tab in st.session_state["tabs"]:
        current_tab_data = st.session_state["tabs"][current_tab]
    else:
        st.error("The selected tab no longer exists. Creating a new tab.")
        create_new_tab()  # Create a new tab if the current one is invalid
        current_tab = st.session_state["current_tab"]
        current_tab_data = st.session_state["tabs"][current_tab]
else:
    st.error("No tabs available. Creating a new tab.")
    create_new_tab()
    current_tab = st.session_state["current_tab"]
    current_tab_data = st.session_state["tabs"][current_tab]

st.title("Python Code Reviewer")

# Code Editor
code = st_ace(
    language="python",
    theme="monokai",
    height=300,
    value=current_tab_data["code"],
    key=f"editor_{current_tab}_{current_tab_data['editor_key']}"
)

# Update code in session state and database
st.session_state["tabs"][current_tab]["code"] = code
if st.session_state.get('username'):
    save_review(st.session_state['username'], current_tab, st.session_state["tabs"][current_tab])

# Chat-like interface
chat_container = st.container()

with chat_container:
    # Run Code Section
    if st.button("Run Code", key=f"run_{current_tab}"):
        if code.strip():
            result = run_code(code, current_tab)
            st.session_state["tabs"][current_tab]["run_output"] = result
            if st.session_state.get('username'):
                save_review(st.session_state['username'], current_tab, st.session_state["tabs"][current_tab])
        else:
            st.warning("Please enter some code.")

    if current_tab_data["run_output"]:
        st.markdown("#### Output:")
        st.code(current_tab_data["run_output"])

    # Code Review Section
    if st.button("Review Code", key=f"review_{current_tab}"):
        if code.strip():
            review_code(code, current_tab)
        else:
            st.warning("Please enter some code.")

    if current_tab_data["review_output"]:
        st.markdown("#### Review Feedback:")
        st.markdown(current_tab_data["review_output"])
        
        if current_tab_data["fixed_code"]:
            if st.button("Apply Fixed Code", key=f"apply_{current_tab}"):
                apply_fixed_code(current_tab)
                st.rerun()