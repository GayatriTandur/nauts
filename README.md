# Cyber security

## 📋 Project Submission

**Project Name**: CyberSentinel
**Team Members**: Gayatri, Gouri, Prachi, Pragnya Kollad
**Track**: Cybersecurity

---

## 🚀 Project Overview
Security Analysts suffer from "Alert Fatigue." Traditional systems flag thousands of issues, but humans can't investigate them all fast enough. CyberSentinel uses a **Multi-Agent System (MAS)** to act as a digital security team. It doesn't just flag threats; it investigates, remembers past context, and proposes fixes.

## 🏗️ Architecture
- **Inference**: Multi-Agent Reasoning (LLM-based). swarm" of AI agents powered by Gemini 1.5 and GPT-4o
- **Data Pipeline**: MCP-Driven Log Normalization, MCP to turn messy security logs (CSV/JSON) into high-quality context that the AI can actually "understand" and analyze in real-time.
- **Frontend**: Streamlit Security Dashboard

## 📹 Demo
https://youtu.be/pWS_Tmfq_gc?si=2RQeYlRWI1R0f3GZ

---

## ✅ Pre-Submission Checklist
- [ ] **Code Runs**: Everything in `/src` executes without error.
- [ ] **Dependencies**: All external libraries are listed in `requirements.txt`.
- [ ] **Environment**: Provided a `.env.example` if API keys are required.
- [ ] **Screenshots**: Added visual proof to the `/screenshots` folder.
- [ ] **Demo Instructions**: README clearly explains how to run the prototype.

---

## 🛠️ How to Run Locally
1. Clone this repo.
2. `pip install -r requirements.txt`
3. Add your keys to `.env`.
4. Run `python src/main.py`.
