import socket
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
import joblib
import traceback
import time
import hashlib
import base64
import struct

from crypto_utils import (
    generate_rsa_keypair,
    rsa_encrypt, rsa_decrypt,
    generate_aes_key, aes_encrypt, aes_decrypt
)

from utils.chat_history import save_encrypted_message

def fingerprint_hex(pk_bytes, length=16):
    """Return a compact fingerprint for display (hex groups)."""
    h = hashlib.sha256(pk_bytes).hexdigest()[: length * 2]
    return ":".join(h[i:i+4] for i in range(0, len(h), 4))

# ---------------- Framing helpers (length-prefixed) ----------------
def pack_frame(kind: bytes, payload: bytes) -> bytes:
    b64 = base64.b64encode(payload)
    body = kind + b":" + b64
    return struct.pack(">I", len(body)) + body

def unpack_frame_from_buffer(buf: bytearray):
    if len(buf) < 4:
        return None
    length = struct.unpack(">I", bytes(buf[:4]))[0]

    if len(buf) < 4 + length:
        return None
    frame = bytes(buf[4:4+length])

    if b":" not in frame:
      
        del buf[:4+length]
        return None
    kind, b64 = frame.split(b":", 1)

    try:
        payload = base64.b64decode(b64)
    except Exception as e:
       
        print("[DEBUG] base64 decode error:", e)
        del buf[:4+length]
        return None
   
    del buf[:4+length]
    return kind, payload

# ---------------- Chat Client ----------------
class ChatClient:
    def __init__(self):
        # RSA keys (bytes)
        self.private_key, self.public_key = generate_rsa_keypair()
        self.partner_public_key = None
        self.aes_key = None

        # Handshake state
        self.handshake_done = False
        self.aes_sent = False
        self.partner_key_verified = False

        # ML model 
        try:
            
            self.model = joblib.load("spam_model.joblib")
            self.vectorizer = joblib.load("vectorizer.joblib")
            print("[DEBUG] ML model and vectorizer loaded.")
        except FileNotFoundError:
            print("[DEBUG] ML model files not found; continuing without ML. Run ml_train.py first.")
            self.model = None
            self.vectorizer = None

  
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._recv_buf = bytearray()

        self.gui_done = False
        self.running = True

        # resend attempts for public key
        self._max_key_resend = 8

        self.gui_loop()

    # ---------------- ML ----------------
    def is_spam(self, text):
        if not self.model or not self.vectorizer:
            return False
        try:
            message_content = text.split(': ', 1)[-1] if ': ' in text else text
            X = self.vectorizer.transform([message_content])
            pred = self.model.predict(X)
            return pred[0] == "spam"
        except Exception as e:
            print(f"[DEBUG] ML error on text '{text}': {e}")
            return False

    # ---------------- GUI ----------------
    def gui_loop(self):
        self.win = tk.Tk()
        self.win.title("Secure Chat App")
        self.win.geometry("360x680") 
        self.win.resizable(False, False)
        
        self.bg_color = "#F4F7F9"       
        self.header_color = "#192A56"   
        self.chat_area_bg = "#FFFFFF"  
        self.input_bg = "#FFFFFF"
        self.accent_color = "#2ECC71"   
        self.sender_bubble_color = "#A2C0F0" 
        self.receiver_bubble_color = "#E5E7EB" 
        self.text_color = "#1A1A1A"
        self.spam_fg = "#E74C3C"       

        self.win.configure(bg=self.bg_color)
        
        # ---  Header Frame ---
        header = tk.Frame(self.win, bg=self.header_color, height=56)
        header.pack(fill="x")
        tk.Label(header, text="Secure Chat", fg="white", bg=self.header_color,
                 font=("Arial", 14, "bold")).pack(side="left", padx=12, pady=10)
        tk.Label(header, text="E2E + ML", fg="#BDC3C7", bg=self.header_color,
                 font=("Arial", 9)).pack(side="right", padx=10, pady=12)

        # --- Main Content Frame ---
        main_frame = tk.Frame(self.win, bg=self.bg_color)
        main_frame.pack(fill="both", expand=True, padx=8, pady=8)

        # Chat Area 
        self.text_area = tk.Text(main_frame, state="normal", wrap="word",
                                 bg=self.chat_area_bg, fg=self.text_color, bd=0, padx=5, pady=5,
                                 font=("Arial", 10), relief="flat", height=20)
        self.text_area.pack(fill="both", expand=True, pady=(0, 8))
        
        # Standard Info/Error Tags
        self.text_area.tag_config("info", foreground="#3498DB", font=("Arial", 10, "italic"))
        self.text_area.tag_config("debug", foreground="#7F8C8D", font=("Arial", 8))
        self.text_area.tag_config("error", foreground=self.spam_fg, font=("Arial", 10, "bold"))

        self.text_area.tag_config("self_msg", 
                                  foreground="#1A1A1A", 
                                  background=self.sender_bubble_color, 
                                  font=("Arial", 10), 
                                  justify="right", 
                                  lmargin1=10, lmargin2=10, rmargin=10, 
                                  borderwidth=0, 
                                  relief="flat")
                                  
        # Partner Message 
        self.text_area.tag_config("partner_msg", 
                                  foreground="#1A1A1A", 
                                  background=self.receiver_bubble_color, 
                                  font=("Arial", 10), 
                                  justify="left", 
                                  lmargin1=10, lmargin2=10, rmargin=10, 
                                  borderwidth=0, 
                                  relief="flat")
        
        # Spam Monitor Area
        tk.Label(main_frame, text="SPAM MONITOR", bg=self.bg_color, fg=self.spam_fg,
                 font=("Arial", 9, "bold")).pack(anchor="w")
        self.spam_area = tk.Text(main_frame, state="normal", height=4, wrap="word",
                                 bg="#FADBD8", fg=self.spam_fg, bd=1, padx=8, pady=8,
                                 font=("Arial", 9), relief="flat")
        self.spam_area.pack(fill="x", expand=False, pady=(0, 6))
        self.spam_area.config(state="disabled") 

        # --- Input Frame  ---
        input_frame = tk.Frame(self.win, bg=self.bg_color)
        input_frame.pack(fill="x", padx=8, pady=(0, 8))
        
        self.input_area = tk.Text(input_frame, height=3, bg=self.input_bg, fg=self.text_color, 
                                 bd=1, padx=8, pady=8, relief="solid", highlightthickness=0,
                                 font=("Arial", 10))
        self.input_area.pack(side="left", fill="x", expand=True, padx=(0, 8))
        
        self.send_button = tk.Button(input_frame, text="Send", command=self.write,
                                     bg=self.accent_color, fg="white", bd=0, padx=16, pady=6,
                                     font=("Arial", 10, "bold"), activebackground="#27AE60", relief="flat")
        self.send_button.pack(side="right")
      
        self.input_area.bind('<Return>', lambda event: self.write() if not event.state & 0x1 else 'break')


        # --- Status Label ---
        self.handshake_label = tk.Label(self.win, text="⏳ Waiting for connection details...",
                                         fg="#7F8C8D", bg=self.bg_color, font=("Arial", 9))
        self.handshake_label.pack(fill="x", padx=10, pady=(0,5))

        # connect popup
        host = simpledialog.askstring("Host", "Enter server IP (e.g. 127.0.0.1):", parent=self.win)
        if not host:
            self.stop(); return
        name = simpledialog.askstring("Name", "Enter your name:", parent=self.win)
        if not name:
            self.stop(); return
        self.name = name

        try:
            self.client.connect(("127.0.0.1", 5000)) 
            print(f"[DEBUG] Connected to server 127.0.0.1:5000")
            self.text_area.insert("end", f"[INFO] Connected to server.\n", "info")
            self.handshake_label.config(text="⏳ Connected. Waiting for partner to exchange keys...")
        except Exception as e:
            messagebox.showerror("Connection Error", f"Could not connect to server: {e}")
            self.text_area.insert("end", f"[ERROR] Could not connect: {e}\n", "error")
            self.stop(); return

        # start receiver thread
        threading.Thread(target=self.receive, daemon=True).start()
        print("[DEBUG] Started receive thread.")

        # send KEY and limited resend thread
        self.send_key_once_then_resend_limited()

        # Disable main text area for editing after setup
        self.text_area.config(state="disabled")

        self.gui_done = True
        self.win.protocol("WM_DELETE_WINDOW", self.stop)
        self.win.mainloop()

    def _insert_message(self, text, tag):
        """Helper to insert message with tag and auto-scroll, adding padding newlines."""
        self.text_area.config(state="normal") 
        
        self.text_area.insert("end", "\n") 
        
        max_message_width = 40
        
        if tag == "self_msg":
            text_length = len(text)
            padding_needed = max(0, max_message_width - text_length)
            content_to_insert = " " * padding_needed + f" {text} " 
            self.text_area.insert("end", content_to_insert, tag) 
        elif tag == "partner_msg":
            self.text_area.insert("end", f" {text} ", tag)
        else:
            self.text_area.insert("end", text, tag)

        self.text_area.insert("end", "\n")
        self.text_area.see("end")
        
        self.text_area.config(state="disabled") 

    def send_key_once_then_resend_limited(self):
        try:
            self._send_frame_key(self.public_key)
            if self.gui_done:
                 self.text_area.config(state="normal")
                 self.text_area.insert("end", "[DEBUG] Sent public key.\n", "debug")
                 self.text_area.config(state="disabled")
        except Exception as e:
            print("[DEBUG] Error sending public key:", e)
        threading.Thread(target=self._periodic_resend_key_limited, daemon=True).start()

    def _periodic_resend_key_limited(self):
        """Resends the public key up to max attempts while waiting for a partner key."""
        attempts = 0
        while (self.running and not self.handshake_done and self.partner_public_key is None
               and attempts < self._max_key_resend):
            time.sleep(1.5) 
            try:
                self._send_frame_key(self.public_key)
                print(f"[DEBUG] (resend#{attempts+1}) Sent public key.")
            except Exception:
                break 
            attempts += 1
            
        if attempts >= self._max_key_resend and self.partner_public_key is None:
            print("[DEBUG] Reached maximum KEY resend attempts without partner key.")
            if self.gui_done:
                self.text_area.config(state="normal")
                self.text_area.insert("end", "[WARNING] Failed to receive partner key after max attempts. Session may be unstable.\n", "error")
                self.text_area.config(state="disabled")

    # ---------------- wire send helpers ----------------
    def _send_frame(self, kind: bytes, raw_payload: bytes):
        """Packs and sends a frame over the socket."""
        frame = pack_frame(kind, raw_payload)
        try:
            self.client.sendall(frame)
        except Exception as e:
            print("[DEBUG] send frame error:", e)
            self.stop()

    def _send_frame_key(self, key_bytes: bytes):
        self._send_frame(b"KEY", key_bytes)

    def _send_frame_aes(self, enc_aes_bytes: bytes):
        self._send_frame(b"AES", enc_aes_bytes)

    def _send_frame_msg(self, packet_bytes: bytes):
        self._send_frame(b"MSG", packet_bytes)

    # ---------------- sending message ----------------
    def write(self):
        """
        Handles sending a message, checking ML for spam first, and logging for audit.
        """
        text = self.input_area.get("1.0", "end-1c").strip()
        self.input_area.delete("1.0", "end") 
        if not text:
            return
            
        if not self.handshake_done:
            self.text_area.config(state="normal")
            self.text_area.insert("end", "⏳ Waiting for encryption handshake to complete...\n", "info")
            self.text_area.config(state="disabled")
            return
            
        # Check for spam
        if self.is_spam(text):
            self._insert_message(
                f"⚠ WARNING (Outgoing): Message '{text}' detected as SPAM. Blocked.", "error"
            )
            
            if self.gui_done:
                self.spam_area.config(state="normal")
                self.spam_area.insert("end", f"[BLOCKED] You: {text}\n")
                self.spam_area.see("end")
                self.spam_area.config(state="disabled")
            
            # ---------------- Audit Logging ----------------
            try:
                audit_entry = {
                    "timestamp": time.time(),
                    "sender": self.name,
                    "msg_hash": hashlib.sha256(text.encode()).hexdigest(),
                    "classification": "spam"
                }
                with open("spam_audit.log", "a") as f:
                    f.write(str(audit_entry) + "\n")
            except Exception as e:
                print("[DEBUG] Audit log failed:", e)
            
            return  

    # ---------------- Normal Sending ----------------
        try:
            plaintext = f"{self.name}: {text}"
            nonce, ciphertext, tag = aes_encrypt(self.aes_key, plaintext)
            packet = nonce + b"<SEP>" + ciphertext + b"<SEP>" + tag
            self._send_frame_msg(packet)
            
            save_encrypted_message("history.bin", ciphertext) 
            
            self._insert_message(f"{self.name}: {text}", "self_msg")
        
        except Exception as e:
            print("[DEBUG] Send error:", e)
            self.text_area.config(state="normal")
            self.text_area.insert("end", f"[ERROR] Send failed: {e}\n", "error")
            self.text_area.config(state="disabled")
            traceback.print_exc()


    # ---------------- receive loop ----------------
    def receive(self):
        """Receives data chunks and processes full frames from the buffer."""
        while self.running:
            try:
                data = self.client.recv(4096)
                if not data:
                    print("[DEBUG] Server disconnected.")
                    break
                self._recv_buf.extend(data)
                while True:
                    res = unpack_frame_from_buffer(self._recv_buf)
                    if res is None:
                        break 
                        
                    kind, payload = res
                    try:
                        if kind == b"KEY":
                            self._handle_key(payload)
                        elif kind == b"AES":
                            self._handle_aes(payload)
                        elif kind == b"MSG":
                            self._handle_msg_payload(payload)
                        else:
                            print("[DEBUG] Unknown frame kind:", kind)
                    except Exception as e:
                        print(f"[DEBUG] error handling frame type {kind}: {e}")
                        traceback.print_exc()
                        
            except ConnectionResetError:
                print("[DEBUG] Connection reset by peer.")
                break
            except Exception as e:
                break
        self.stop()

    # ---------------- handshake handlers ----------------
    def _handle_key(self, partner_pk_bytes: bytes):
        """Handles the received partner's public RSA key."""
        if self.partner_public_key is None:
            self.partner_public_key = partner_pk_bytes
            print(f"[DEBUG] Received partner public key (len={len(partner_pk_bytes)} bytes).")
            if self.gui_done:
                self.text_area.config(state="normal")
                self.text_area.insert("end", "[DEBUG] Received partner public key.\n", "debug")
                self.text_area.config(state="disabled")

            # --- Step 1: Verification ---
            our_fp = fingerprint_hex(self.public_key, length=12)
            partner_fp = fingerprint_hex(self.partner_public_key, length=12)
            prompt = (
                "A partner public key was received.\n\n"
                f"Your key fingerprint:\n  {our_fp}\n\n"
                f"Partner key fingerprint:\n  {partner_fp}\n\n"
                "COMPARE this partner fingerprint with what your partner reads over a trusted channel.\n\n"
                "Do you TRUST this partner key to proceed with AES key exchange?"
            )
            
            def ask_trust():
                accepted = messagebox.askyesno("Verify Partner Key", prompt, parent=self.win)
                if not accepted:
                    print("[DEBUG] User rejected partner key.")
                    self.text_area.config(state="normal")
                    self.text_area.insert("end", "[WARNING] Partner key NOT trusted. Handshake halted.\n", "error")
                    self.text_area.config(state="disabled")
                    self.partner_public_key = None
                    return

                self.partner_key_verified = True
                print("[DEBUG] User accepted partner key.")
                self.text_area.config(state="normal")
                self.text_area.insert("end", "[DEBUG] Partner key verified by user.\n", "debug")
                self.text_area.config(state="disabled")
                
                # --- Step 2: Role Determination (Initiator/Receiver) ---
                self._determine_and_send_aes()
            
            self.win.after(0, ask_trust)
            
        else:
            print("[DEBUG] Received duplicate KEY frame. Ignoring.")

    def _determine_and_send_aes(self):
        """Determines if this client is the AES key initiator and sends the key if so."""
        if not self.handshake_done and not self.aes_sent and self.partner_key_verified:
            try:
                
                if self.public_key > self.partner_public_key:
                    self.aes_key = generate_aes_key()
                    enc_key = rsa_encrypt(self.partner_public_key, self.aes_key)
                    self._send_frame_aes(enc_key)
                    self.aes_sent = True
                    self.handshake_done = True
                    
                    print("[DEBUG] Generated and sent AES session key (Initiator).")
                    if self.gui_done:
                        self.handshake_label.config(text="✅ Handshake complete. You are the initiator.")
                        self.text_area.config(state="normal")
                        self.text_area.insert("end", "✅ Encryption handshake complete. You can now send messages.\n", "info")
                        self.text_area.config(state="disabled")
                else:
                    print("[DEBUG] Waiting for AES from partner (Role: Receiver).")
                    if self.gui_done:
                        self.handshake_label.config(text="⏳ Waiting for partner to send AES key...")
                        
            except Exception as e:
                print("[DEBUG] Error during AES role determination/send:", e)
                self.text_area.config(state="normal")
                self.text_area.insert("end", f"[ERROR] Handshake failed: {e}\n", "error")
                self.text_area.config(state="disabled")
                traceback.print_exc()

    def _handle_aes(self, enc_bytes: bytes):
        """Handles the received RSA-encrypted AES key (Receiver role)."""
        if not self.partner_key_verified:
            print("[DEBUG] Received AES but partner key not verified — ignoring AES.")
            if self.gui_done:
                self.text_area.config(state="normal")
                self.text_area.insert("end", "[WARNING] Received AES but partner key not verified — ignored.\n", "error")
                self.text_area.config(state="disabled")
            return
            
        try:
            if not self.handshake_done:
                # Decrypt AES using private key
                self.aes_key = rsa_decrypt(self.private_key, enc_bytes)
                self.handshake_done = True
                print("[DEBUG] Received and decrypted AES session key (Receiver).")
                if self.gui_done:
                    self.handshake_label.config(text="✅ Handshake complete. You are the receiver.")
                    self.text_area.config(state="normal")
                    self.text_area.insert("end", "✅ Encryption handshake complete. You can now send messages.\n", "info")
                    self.text_area.config(state="disabled")
            else:
                print("[DEBUG] Received duplicate AES frame. Ignoring.")
        except Exception as e:
            print("[DEBUG] AES decrypt error (Key is likely corrupt/invalid):", e)
            self.text_area.config(state="normal")
            self.text_area.insert("end", f"[ERROR] Failed to decrypt AES key. Handshake failed: {e}\n", "error")
            self.text_area.config(state="disabled")
            traceback.print_exc()

    # ---------------- incoming msg ----------------
    def _handle_msg_payload(self, packet_bytes: bytes):
        """Handles incoming AES-encrypted messages."""
        if not self.handshake_done:
            print("[DEBUG] Ignoring MSG before handshake.")
            return
        try:
            parts = packet_bytes.split(b"<SEP>")
            if len(parts) != 3:
                print("[DEBUG] MSG malformed, parts:", len(parts))
                return
            nonce, ciphertext, tag = parts
            
            plain = aes_decrypt(self.aes_key, nonce, ciphertext, tag)
            
            # ML Spam Detection 
            if self.gui_done:
                if self.is_spam(plain):
                    self.spam_area.config(state="normal")
                    self.spam_area.insert("end", f"[SPAM] {plain}\n")
                    self.spam_area.see("end")
                    self.spam_area.config(state="disabled")
                else:
                    self._insert_message(plain, "partner_msg")
                    
        except Exception as e:
            print("[DEBUG] Decrypt error (Message may be corrupt or wrong key):", e)
            if self.gui_done:
                self.text_area.config(state="normal")
                self.text_area.insert("end", "[ERROR] Message integrity check failed (Decryption Error).\n", "error")
                self.text_area.config(state="disabled")
            traceback.print_exc()

    def stop(self):
        """Gracefully shuts down the client application."""
        if not self.running:
            return
        print("[DEBUG] Stopping client...")
        self.running = False
        try:
            try:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
            except:
                pass
        finally:
            if self.gui_done:
                try:
                    self.win.destroy()
                except:
                    pass


if __name__ == "__main__":
    ChatClient()