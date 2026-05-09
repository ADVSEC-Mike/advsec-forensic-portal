import streamlit as st
import pandas as pd
from google import genai
from pypdf import PdfReader
import requests
from io import BytesIO
from datetime import datetime
import re
import time

# --- ADVSEC CREDENTIALS ---
API_KEY = st.secrets["GEMINI_API_KEY"]
client = genai.Client(api_key=API_KEY)

# --- FORENSIC HELPERS ---
def get_seal_forensics(reader):
    try:
        catalog = reader.root_object
        if "/AcroForm" in catalog:
            acro = catalog["/AcroForm"]
            if "/Fields" in acro:
                for field_ref in acro["/Fields"]:
                    field = field_ref.get_object()
                    if field.get("/FT") == "/Sig":
                        signer = field.get("/V", {}).get("/Name", "Verified Certificate")
                        return f"✅ SEALED ({signer})"
        return "None"
    except: return "None"

def harvest_xmp_url(xmp_str):
    match = re.search(r"<xmpRights:WebStatement>(.*?)</xmpRights:WebStatement>", xmp_str)
    return match.group(1) if match else "NOT DETECTED"

# --- UI COMPONENT FOR STATUS BADGES ---
def display_sovereignty_status(m):
    score = 0
    if m['Title'] != 'MISSING': score += 1
    if m['Author'] != 'MISSING': score += 1
    if m['Copyright-Notice'] != 'NOT DETECTED': score += 1
    if "✅" in m['Cert-Status']: score += 2
    if "✅" in m['JS-Status']: score += 1

    if score >= 5:
        st.success("🔒 **DOCUMENT STATUS: SECURE & AI-FRIENDLY**")
    elif score >= 3:
        st.warning("⚠️ **DOCUMENT STATUS: COMPLIANCE WARNING**")
    else:
        st.error("🚨 **DOCUMENT STATUS: SOVEREIGNTY RISK**")

# --- THE DEEP-SCAN ENGINE ---
def perform_deep_scan(pdf_stream, filename):
    reader = PdfReader(pdf_stream)
    meta = reader.metadata or {}
    raw_root = str(reader.root_object)
    xmp_raw = ""
    try:
        xmp_obj = reader.root_object.get('/Metadata', {})
        if xmp_obj:
            xmp_raw = str(xmp_obj.get_object().get_data(), 'utf-8', 'ignore')
    except: xmp_raw = ""

    raw_content = pdf_stream.getvalue().decode('latin-1', errors='ignore')
    js_found = "/JS" in raw_content or "/JavaScript" in raw_content
    cve_trigger = "app.beginPriv" in raw_content or "app.trustedFunction" in raw_content

    if cve_trigger: js_display = "🚨 THREAT (CVE-2026-34621)"
    elif js_found: js_display = "⚠️ JS DETECTED (Logic Ghost)"
    else: js_display = "✅ CLEAN"

    return {
        "File-Name": filename,
        "Cert-Status": get_seal_forensics(reader),
        "meta": meta,
        "xmp": xmp_raw,
        "root": raw_root,
        "js_status": js_display,
        "copy_url": harvest_xmp_url(xmp_raw)
    }

# --- PAGE UI ---
st.set_page_config(page_title="ADVSEC Forensic Portal", layout="wide")

# The ADVSEC Executive Header
st.image("logo-advsec.jpg", width=500) 

st.markdown('<p style="font-size: 30px; font-weight: 800; color: #1E3A8A;">🛡️ ADVSEC - PDF Metadata Forensic Testing Portal</p>', unsafe_allow_html=True)

if 'processing' not in st.session_state: st.session_state.processing = False
if 'messages' not in st.session_state: st.session_state.messages = []
if 'manifest_data' not in st.session_state: st.session_state.manifest_data = None

@st.dialog("ADVSEC Forensic Shield")
def show_shield():
    st.warning("⚠️ **PDF Metadata SCAN AUTHORIZED**")
    st.write("This audit scans the referenced PDF for Layer-3 Metadata and performs a Deep Scan for user-fields, Copyright Status, Certificates, & embedded executable logic (JavaScript). No content from any of the three layers in the referenced PDF is stored or shared.")
    if st.button("CONFIRM & EXECUTE"):
        st.session_state.processing = True
        st.session_state.messages = [] 
        st.session_state.manifest_data = None # Ensure clean slate
        st.rerun()

input_type = st.radio("Input Method:", ["Paste PDF URL", "Upload PDF"])
pdf_data, current_filename = None, "Unknown.pdf"

if input_type == "Paste PDF URL":
    url_in = st.text_input("Enter URL:", placeholder="https://yourDOMAIN.com/document.pdf")
    if url_in:
        try:
            res = requests.get(url_in, timeout=10)
            pdf_data = BytesIO(res.content)
            current_filename = url_in.split("/")[-1]
        except: st.error("Link Error")
else:
    uploaded = st.file_uploader("Drop PDF", type="pdf")
    if uploaded:
        pdf_data = BytesIO(uploaded.read())
        current_filename = uploaded.name

if pdf_data and not st.session_state.processing:
    if st.button("START SCAN"): show_shield()

# --- THE REPORT & INTERACTIVE CHAT ---
if st.session_state.processing:
    # Scan logic
    if st.session_state.manifest_data is None:
        results = perform_deep_scan(pdf_data, current_filename)
        meta = results["meta"]
        st.session_state.manifest_data = {
            "Audit-Report-Date": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "Title": meta.get('/Title', 'MISSING'),
            "File-Name": results["File-Name"],
            "Author": meta.get('/Author', 'MISSING'),
            "Subject": meta.get('/Subject', 'MISSING'),
            "Keywords": meta.get('/Keywords', 'MISSING'),
            "Producer": meta.get('/Producer', 'MISSING'),
            "Copyright-Notice": meta.get('/Copyright', 'NOT DETECTED'),
            "Copyright-URL": results["copy_url"],
            "Cert-Status": results["Cert-Status"],
            "JS-Status": results["js_status"],
            "xmp_dna": results["xmp"][:2000],
            "raw_root": results["root"]
        }

    # CRITICAL: Define 'm' globally within this block for UI and Chat
    m = st.session_state.manifest_data

    # 1. Display Sovereignty Status Badge
    display_sovereignty_status(m)

    # 2. Display Manifest Table
    st.subheader("📋 Audit Manifest Summary")
    df = pd.DataFrame([m]).T
    df.columns = ["Forensic Value"]
    st.dataframe(df, use_container_width=True)

    # --- THE INTELLIGENCE LAYER ---
    st.divider()
    st.markdown("### 🛡️ Interactive Auditor Analysis")
    
    # Display previous messages
    for message in st.session_state.messages:
        with st.chat_message(message["role"], avatar="🛡️" if message["role"] == "assistant" else "👤"):
            st.markdown(message["content"])

    # Initial Audit (Retry Logic Included)
    if not st.session_state.messages:
        with st.spinner("Lead Auditor is reviewing the manifest..."):
            initial_prompt = f"""
            Act as the ADVSEC Lead Auditor. Review this manifest: {m}.
            
            ### AUDIT RULES & TRIGGERS:
            1. STRIPPED METADATA: If Title, Author, Subject, Keywords, and Copyright are all missing, flag this as 'Network Stripping'.
            2. PII VIOLATION: If personal names appear in the Author field, flag as a PII Violation.
            3. CORPORATE IP RISK: If Keywords contain alphanumeric strings (Canva IDs) AND Producer is 'Canva', flag as a 'Corporate IP Security Risk'.
            4. OWNERSHIP GAP: If Copyright Notice & URL are missing, state: 'Document ownership is unanchored in the AI architecture.'
            5. PROVENANCE FAILURE: If Certificate is 'None', state: 'Document authenticity cannot be verified; provenance is null.'
            6. INFRASTRUCTURE LEAK: Software versions or OS paths are 'Cybersecurity Red Flags'.

            Identify Ghosts/Compliance Violations/Canva Trackers/JAVA Threats. 
            Keep it professional and professionally clear.
            """
            for attempt in range(3):
                try:
                    response = client.models.generate_content(model="gemini-2.5-flash", contents=initial_prompt)
                    st.session_state.messages.append({"role": "assistant", "content": response.text})
                    st.rerun()
                    break 
                except Exception as e:
                    if "503" in str(e) and attempt < 2:
                        time.sleep(2 * (attempt + 1))
                        continue
                    else:
                        st.error(f"Auditor Offline (503). {e}")
                        break

    # User Chat Input
    if prompt := st.chat_input("Ask a follow-up question..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user", avatar="👤"):
            st.markdown(prompt)

        with st.chat_message("assistant", avatar="🛡️"):
            with st.spinner("Analyzing..."):
                full_context = f"Context: Audit of {m['File-Name']}. Manifest: {m}. User Question: {prompt}"
                response = client.models.generate_content(model="gemini-2.5-flash", contents=full_context)
                st.markdown(response.text)
                st.session_state.messages.append({"role": "assistant", "content": response.text})

    # 3. XMP View
    with st.expander("📂 View Advanced Metadata DNA (XMP Window)"):
        st.code(m["xmp_dna"], language="xml")

    if st.button("Reset Portal"):
        st.session_state.processing = False
        st.session_state.manifest_data = None
        st.session_state.messages = []
        st.rerun()