🛡️ Secure ML Chat App
End-to-End Encrypted Chat + ML-Based Spam Detection

(Built in Python – Socket Programming, Cryptography, Tkinter GUI, and Machine Learning)

🚀 Overview

Secure ML Chat App is a modern, end-to-end encrypted messaging application built with Python.
It combines asymmetric encryption, symmetric encryption, and a machine-learning spam classifier to create a secure and intelligent chat system.

This project demonstrates strong skills in:

Network programming

Cryptography

ML model integration

GUI application design

Secure architecture

🔐 Security Features
✔️ End-to-End Encryption (E2EE)

RSA-based key exchange

AES-256 symmetric encryption for fast secure messaging

Automatic handshake and secure session setup

✔️ Forward Secrecy

Session key generated per connection

No plaintext is ever stored

✔️ Encrypted Message History

Chat history is stored in encrypted .bin files

🤖 Machine Learning Features
✔️ Spam Classification

Trained using a TF-IDF vectorizer + Logistic Regression model

Detects phishing, scam, abusive, or spam messages

Spam messages are redirected to a separate “Spam Monitor” panel

Clean messages are delivered normally

✔️ Extensible Model

You can retrain the model by:

Adding more spam/ham messages to the CSV

Re-running train_model.py

🎨 GUI Features (Tkinter – Mobile-Style UI)
✔️ WhatsApp-Like Layout

Purple-themed modern design

Separate colors for sent and received messages

Timestamped message bubbles

Auto-scrolling conversation window

✔️ Clean Organization

Chat Area

Spam Monitor Area

Input Box

Header with connection status

🏗️ Architecture
Client A  <---- encrypted ---->  Server  <---- encrypted ---->  Client B
        RSA + AES                         Broadcast encrypted packets

Technologies Used

Python 3

Tkinter (GUI)

Socket Programming

Cryptography (PyCryptodome)

scikit-learn (ML model)

pickle (model loading)

threading

Project Structure
📦 Secure_ML_Chat_App  
│── client_gui.py
│── server.py
│── spam_model.pkl
│── vectorizer.pkl
│── chat_history.bin
│── train_model.py
│── dataset.csv
│── README.md

Running the Application
1️⃣ Start the Server
python server.py
Start Client
python client_gui.py

Enter:

Server IP

Username

The app automatically performs:

Key exchange

AES session key generation

Secure communication setup

Training Your Own Spam Detection Model

Update the CSV dataset with your own messages, then run:
python ml_train.py

It will generate:

spam_model.pkl

vectorizer.pkl

The GUI client will automatically load them.

Requirements

Install dependencies:
pip install -r requirements.txt
Example requirements.txt:
tk
scikit-learn
cryptography
pycryptodome
pandas

