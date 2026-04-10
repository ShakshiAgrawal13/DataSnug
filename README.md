# 🛡️ DataSnug — AI-Powered Data Loss Prevention

> Built for **Intrusion Hackathon** | AI/ML Track | Problem #10

---

## 📁 Folder Structure

```
DataSnug/
├── app.py                    ← Flask backend (main server)
├── requirements.txt          ← Python dependencies
├── models/
│   ├── __init__.py
│   └── detector.py           ← AI detection engine (regex + risk scoring)
├── static/
│   ├── css/
│   │   └── style.css         ← Dashboard styling
│   └── js/
│       └── main.js           ← Frontend logic
├── templates/
│   └── index.html            ← Main dashboard UI
├── data/
│   └── sample_data.txt       ← Test file with sensitive data
└── README.md
```

---

## 🚀 How to Run (Step by Step)

### 1. Install Python
Download from https://python.org (Python 3.8 or higher)

### 2. Open terminal in the DataSnug folder

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the app
```bash
python app.py
```

### 5. Open browser
Go to: **http://localhost:5000**

---

## 🔍 What DataSnug Detects

| Data Type              | Risk Level |
|------------------------|------------|
| Credit Card Numbers    | 🔴 HIGH    |
| SSN / Aadhaar          | 🔴 HIGH    |
| Passwords (plaintext)  | 🔴 HIGH    |
| API Keys / Tokens      | 🔴 HIGH    |
| Email Addresses        | 🟡 MEDIUM  |
| Phone Numbers          | 🟡 MEDIUM  |
| Bank Account Numbers   | 🟡 MEDIUM  |
| IP Addresses           | 🔵 LOW     |

---

## 🧪 Testing

1. Click **"Quick Test Samples"** buttons on the dashboard
2. Upload `data/sample_data.txt` using the File Scan tab
3. Paste your own text in the Text Scan tab

---

## 💡 How It Works

1. **Input** → User pastes text or uploads a file
2. **Detection** → AI engine scans using pattern recognition + regex
3. **Risk Scoring** → Each finding is weighted and a total risk score is calculated
4. **Alert** → Dashboard shows findings with masked sensitive data
5. **Log** → All scans are logged in the Live Alert panel

---

## 🏆 Hackathon Pitch Points

- Real-time sensitive data detection
- Supports multiple data types (PII, financial, credentials)
- Risk scoring system (HIGH / MEDIUM / LOW / SAFE)
- File and text scanning
- Live alert log with timestamps
- Data masking (never exposes raw sensitive data)
- Prevents unauthorized data exfiltration
