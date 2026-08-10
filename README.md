# 🛡️ ScamShield

### Explainable Detection and Risk Analysis of Scam & Phishing Messages

**HackMatrix 2K26 — Solo Project**

> **Think before you click.**

ScamShield is a web-based message risk analysis platform designed to help users identify suspicious SMS, emails, and direct messages before interacting with them.

Instead of providing only a simple *safe/unsafe* verdict, ScamShield analyzes suspicious signals in a message, generates a **0–100 risk score**, classifies the message into a risk level, and explains the detected warning signals with supporting evidence and a safety recommendation.

---

## 📌 Problem Statement

Scam and phishing messages often use urgency, threats, financial requests, rewards, and verification demands to manipulate users into taking unsafe actions.

Many users find it difficult to recognize these warning signs, while conventional spam detection may provide little explanation about **why** a message is considered suspicious.

ScamShield addresses this problem by providing an **explainable, signal-based risk assessment** for suspicious messages.

---

## 💡 Solution Overview

ScamShield follows a simple user-centered workflow:

```text
User submits message
        ↓
Input validation
        ↓
Message analysis
        ↓
Suspicious signal detection
        ↓
Risk score calculation
        ↓
Risk classification
        ↓
Evidence + recommendation
        ↓
Scan saved to case history
```

The system converts detected signals into an understandable risk assessment so that users can make more informed decisions before clicking links, sharing information, or responding to suspicious messages.

---

## ✨ Key Features

### 🔍 Message Risk Analysis

Analyze suspicious SMS, email, or direct-message text through a simple web interface.

### ⚠️ Risk Classification

Messages are classified as:

* **LOW RISK**
* **MEDIUM RISK**
* **HIGH RISK**

### 📊 Explainable Risk Score

Every analysis produces a risk score between **0 and 100**.

### 🧩 Signal-Based Evidence

Detected warning signals are displayed with their category, description, and supporting evidence.

### 💡 Safety Recommendation

The system provides a recommendation based on the detected risk.

### 🗂️ Scan History

Previous analyses are stored locally using SQLite and displayed in the **Recent Scans** section.

### ⌨️ Keyboard Support

`Ctrl + Enter` can be used to trigger message analysis.

### 🔒 Input Validation

The application validates empty messages and limits input to **5000 characters**.

---

## 🔎 Detection Signals

ScamShield evaluates messages for suspicious characteristics such as:

* Urgency and pressure
* Threats or fear-based language
* Financial requests
* Reward or prize claims
* Verification demands
* Suspicious URL characteristics

The detected signals are presented to the user rather than hiding the reasoning behind the result.

---

## 🖥️ Prototype Screenshots

### 1. Message Analysis Interface

<img width="900" alt="ScamShield Message Analysis Interface" src="https://github.com/user-attachments/assets/8b03c7d5-f34d-4c9b-bb3c-5450cf527dcf" />

### 2. Risk Assessment & Detected Signals

<img width="900" alt="ScamShield Risk Assessment" src="https://github.com/user-attachments/assets/b24a3fb6-3e77-496b-876e-313f4b4862bb" />

### 3. Recent Scan History

<img width="900" alt="ScamShield Recent Scan History" src="https://github.com/user-attachments/assets/545ca1c4-634a-4e97-a912-fb0efe5b86c0" />

## 🎥 Demo
[Watch the ScamShield Demo]
https://drive.google.com/drive/folders/1sgqRT83I3aPcYazY-o3-cgqYtMsLGY10

## 🏗️ System Architecture

```text
                    USER
                      │
                      ▼
              ScamShield Web UI
                      │
                      ▼
               Flask Application
                      │
                      ▼
              Message Analyzer
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
   Signal Detection          Risk Scoring
          │                       │
          └───────────┬───────────┘
                      ▼
             Explainable Result
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
    Recommendation            Risk Score
          │
          ▼
      SQLite Database
          │
          ▼
     Recent Scan History
```

---

## 🛠️ Technology Stack

| Layer         | Technology                                  |
| ------------- | ------------------------------------------- |
| Frontend      | HTML5, CSS3, JavaScript                     |
| Backend       | Python, Flask                               |
| Database      | SQLite                                      |
| Analysis      | Signal / rule-based message analysis        |
| Data Handling | JSON                                        |
| UI Typography | Space Grotesk, IBM Plex Sans, IBM Plex Mono |

---

## 📂 Project Structure

```text
X-HackMatrix2026/
│
├── app.py
│
├── detector/
│   └── analyzer.py
│
├── database/
│   ├── database.py
│   └── scamshield.db
│
├── templates/
│   └── index.html
│
├── static/
│   ├── style.css
│   └── script.js
│
├── requirements.txt
│
└── README.md
```

Additional submission materials such as the presentation, project documentation, screenshots, and demonstration video may also be included in the repository.

---

## ⚙️ Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/AI-Engineer000/X-HackMatrix2026.git
cd X-HackMatrix2026
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

### 3. Activate the environment

**Windows:**

```bash
venv\Scripts\activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Run the application

```bash
python app.py
```

### 6. Open the application

Open the local Flask address shown in the terminal, typically:

```text
http://127.0.0.1:5000
```

---

## 🚀 Usage

1. Open the ScamShield web interface.
2. Paste the suspicious message into the analyzer.
3. Click **Analyze Message**.
4. Review the generated risk level and score.
5. Examine the detected signals and supporting evidence.
6. Read the safety recommendation.
7. Review previous scans under **Recent Scans**.

---

## 📊 Example Output

A typical analysis provides:

```text
Risk Level: HIGH RISK

Risk Score: 82 / 100

Detected Signals:
• Suspicious urgency
• Financial request
• Verification demand

Evidence:
Relevant phrases detected in the submitted message.

Recommendation:
Review the detected warning signs carefully before
responding, clicking links, or sharing information.
```

*The actual score and signals depend on the submitted message.*

---

## 🔐 Data & Privacy

ScamShield stores analyzed messages and their results in a local SQLite database for scan-history functionality.

The current prototype is designed for local demonstration and does not require a public deployment to operate.

---

## 🔮 Future Scope

Potential future enhancements include:

* Machine-learning and NLP-based classification
* Multilingual scam-message analysis
* Real-time URL reputation checking
* Phishing-domain intelligence
* Screenshot and image-based scam detection
* Browser or messaging-platform integration
* Threat-intelligence integration
* Advanced analytics and reporting

---

## 🎥 Demonstration

The prototype is currently demonstrated through the local Flask application.

**Public deployment:** Not available at present.

A demonstration video is included in the repository as part of the HackMatrix 2K26 submission.

---

## 📑 Hackathon Submission

**Hackathon:** HackMatrix 2K26
**Project:** ScamShield
**Participant:** AAKANKSHA VIDUSHI PANDEY
**Repository:** [X-HackMatrix2026](https://github.com/AI-Engineer000/X-HackMatrix2026)

---

## 👩‍💻 Participant

### AAKANKSHA VIDUSHI PANDEY

**Solo Participant — HackMatrix 2K26**

---

## 📜 Disclaimer

ScamShield is a prototype developed for educational and hackathon purposes. Its risk assessment should be treated as a decision-support mechanism and not as a guarantee that a message is safe or malicious.

---

### 🛡️ ScamShield

**Detect the signal. Understand the risk. Think before you click.**

<img width="1026" height="858" alt="Screenshot 2026-08-10 100526" src="https://github.com/user-attachments/assets/8b03c7d5-f34d-4c9b-bb3c-5450cf527dcf" />
<img width="1008" height="869" alt="Screenshot 2026-08-10 100534" src="https://github.com/user-attachments/assets/b24a3fb6-3e77-496b-876e-313f4b4862bb" />
<img width="1031" height="862" alt="image" src="https://github.com/user-attachments/assets/545ca1c4-634a-4e97-a912-fb0efe5b86c0" />

