# Scam Message Investigator

## Project Overview

Scam Message Investigator is an AI-based application designed to identify suspicious messages and detect possible scam activities. It uses Python-based rule detection and the **Gemma 3:1B** language model through **Ollama** to analyse messages and provide explanations.

The application provides a simple Streamlit dashboard where users can enter a message and view its risk level and investigation results.

## Features

- Analyse suspicious text messages.
- Detect common scam-related keywords and patterns.
- Calculate risk scores using Python.
- Generate AI-based explanations using Gemma 3:1B.
- Display Low, Medium, and High risk levels.
- Maintain a simple and user-friendly dashboard.
- Run locally without requiring a paid AI API key.

## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Application development |
| Streamlit | User interface |
| Ollama | Local AI model execution |
| Gemma 3:1B | Message analysis |
| Requests | API communication with Ollama |
| JSON | Data processing |

## Project Structure

```text
Scam_Message_Investigator/
│
├── app.py
├── requirements.txt
└── README.md
```

## Working Procedure

1. User enters a suspicious message.
2. Python checks the message for scam-related indicators.
3. The system calculates a risk score.
4. The message is analysed using the Gemma 3:1B model through Ollama.
5. The application generates an investigation report.
6. The dashboard displays the risk level and analysis.

## Risk Analysis

The system checks for suspicious indicators such as:

- OTP, password, PIN, and banking detail requests.
- Lottery and prize messages.
- Urgent payment requests.
- Unverified job offers.
- Unknown contacts.
- Suspicious shortened URLs.
- Threatening messages.

### Risk Levels

| Risk Score | Risk Level |
|---|---|
| Below 30 | Low |
| 30–59 | Medium |
| 60–100 | High |

*Note: Risk scores are heuristic estimates and do not guarantee whether a message is genuine or fraudulent.*

## Installation and Execution

### Step 1: Install Python

Download Python from [https://www.python.org/](https://www.python.org/).

### Step 2: Install Ollama

Download Ollama from [https://ollama.com/](https://ollama.com/).

### Step 3: Download the Gemma Model

Open the terminal and execute:

```bash
ollama pull gemma3:1b
```

### Step 4: Install Dependencies

Navigate to the project folder and run:

```bash
pip install -r requirements.txt
```

### Step 5: Run the Application

```bash
streamlit run app.py
```

Open the local URL displayed in the terminal, usually:

```text
http://localhost:8501
```

## Advantages

- No paid AI API key required.
- Local AI model execution.
- Simple and interactive dashboard.
- Combines rule-based detection with AI analysis.
- Helps users recognise possible scam messages.

## Future Enhancements

- Tamil and multilingual scam detection.
- Improved scam detection accuracy.
- Downloadable investigation reports.
- More advanced URL analysis.
- Secure database integration for investigation history.

## Conclusion

Scam Message Investigator combines Python, Streamlit, Ollama, and Gemma 3:1B to analyse suspicious messages. It identifies possible scam indicators and provides explanations to help users understand potential risks. The project demonstrates the practical use of local AI models for message analysis without depending on paid AI APIs.
