# Secure ML Chat App

> End-to-end encrypted chat with ML-based spam detection — Python, sockets, PyCryptodome, scikit-learn and Tkinter.

---

## Project Summary

**Secure ML Chat App** is a compact, mobile-style chat application that demonstrates a secure end-to-end encrypted messaging flow combined with machine-learning powered spam detection.  
The project shows practical experience in network programming, cryptography, and integrating ML models into production-like applications.

- **Languages / libs:** Python 3, `socket`, `threading`, `tkinter`, `pycryptodome`, `scikit-learn`, `joblib`, `pandas`
- **Key features:** RSA-based authenticated key exchange, AES session encryption, ML spam classifier, lightweight GUI, encrypted message history, audit logging for blocked messages

---
## High-level architecture

Client A <---(framed: KEY/AES/MSG)---> Server (relay) <---(framed)---> Client B

-Each client generates RSA keypair locally
-Clients share public keys via the server (single, framed send)
-Deterministic initiator creates AES session key, encrypts with partner's RSA public key, sends AES to partner
-Both clients then communicate with AES-encrypted messages
-ML spam classifier runs on sender (blocking + audit) and on receiver (spam monitor)


---

## Security design 

- **Public-key exchange:** Each client sends its RSA public key exactly once (framed). Users verify the partner’s fingerprint before trusting the key (prevents MITM).
- **Initiator selection:** A deterministic rule (byte-wise compare) chooses the initiator — only one side generates and sends the AES session key.
- **Session encryption:** AES (EAX) for authenticated encryption (nonce + ciphertext + tag). AES key is exchanged encrypted with RSA-OAEP.
- **Audit & privacy:** Blocked spam messages are not sent over the network. A small audit log (hash + timestamp + sender ID) is stored locally for compliance without storing plaintext.

---

## Features

### Security
- RSA-2048 for key exchange (PKCS1_OAEP)
- AES (EAX mode) for message confidentiality and integrity
- One-time AES per session (forward secrecy per session)
- Fingerprint verification UI for public keys

### Machine Learning
- TF-IDF vectorizer + scikit-learn classifier (e.g., MultinomialNB)
- Sender-side blocking of messages detected as spam
- Receiver-side spam monitor panel that highlights suspected spam messages
- Audit logging for blocked attempts (`spam_audit.log` with message hash and metadata)

### UX / GUI
- Mobile-sized window (360×640) with professional theme
- Distinct bubble styles for sent vs received messages
- Spam monitor panel
- Inline debug/status messages for development and demonstration

---

## Getting started (local development)

1. **Clone repo**
```bash
git clone https://github.com/<your-username>/secure-ml-chat-app.git
cd secure-ml-chat-app
```
2. **Create venv and install**
```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt

Example requirements.txt:
joblib
scikit-learn
pandas
pycryptodome
tk
```

Note: On many systems tkinter is included with Python. If you get GUI errors, install OS-level tkinter package or use Python distribution that includes Tk.

3. **(Optional) Train the spam model**
Add or edit dataset.csv (columns: label and text where label is spam or ham)
```bash
python ml_train.py
```
This will produce spam_model.joblib and vectorizer.joblib.

4. **Run the server**
```bash
python server.py
```
The server is a simple relay that broadcasts framed messages to connected clients.

5. **Run client(s)**
```bash
python client_gui.py
```
Enter server IP (e.g., 127.0.0.1) and username
When partner connects, verify fingerprint (read it aloud or via trusted channel)
After verification, messages can be exchanged securely

## Wire protocol (for devs)
-**Each frame is length-prefixed:** 4-byte BE length followed by KIND:b64(payload)
-KIND ∈ KEY | AES | MSG
-KEY → raw RSA public key bytes
-AES → RSA OAEP-encrypted AES key bytes
-MSG → nonce + b"<SEP>" + ciphertext + b"<SEP>" + tag
-All payloads are base64-encoded inside the frame to keep ASCII-safe transport.

## ML notes & retraining
Training script: ml_train.py (loads CSV, TF-IDF, trains MultinomialNB — change model to LogisticRegression or others easily)

**To improve model:**
-Add more labeled spam/ham rows to your CSV
-Ensure diverse spam examples (phishing, promos, scam phrases)
-Re-run python ml_train.py
-Keep an evaluation step: hold out test set and print accuracy / confusion matrix to avoid overfitting.

## Logging & audit

-Blocked outgoing spam messages are recorded in spam_audit.log as JSON-like entries (timestamp, sender, message-hash, classification).
-Encrypted message bytes are appended to history.bin via utils/chat_history.py.

## UX/Accessibility notes

-The GUI is intentionally compact (phone-like size) to demonstrate a mobile-friendly layout.
-Colors and bubble styles differentiate sender/receiver messages for clear reading.
-Important developer debug logs appear in both terminal and the GUI status area for demonstration.

## Testing & troubleshooting

**If handshake never completes**:
-Ensure both clients are connected to the same server instance (same IP:port).
-Verify the server forwards raw framed bytes unchanged (the provided server.py simply broadcasts).
-Ensure there are no extra bytes or newline framing mismatches — use the provided framing helpers.

**If you get decryption errors:**
-Confirm the correct RSA key pair is used per client and that AES bytes were not corrupted in transit.
-Recreate keys and restart both clients.

## Screenshot Results
<img width="1365" height="720" alt="image" src="https://github.com/user-attachments/assets/dfc4713d-6cf5-4139-afd4-b0f0403cd879" />

📜 License

This project is licensed under the MIT License.

Developed by Aliza Memon
