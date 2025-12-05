import socket
import threading
import sys
import time

clients = []
LOCK = threading.Lock()

def relay_messages(sender_socket, receiver_socket, sender_addr, receiver_addr):
    """Continuously relays raw framed data between two paired sockets."""
    print(f"[RELAY] Starting relay: {sender_addr[1]} -> {receiver_addr[1]}")
    while True:
        try:
            msg = sender_socket.recv(4096)
            if not msg:
                print(f"[RELAY] Client {sender_addr[1]} disconnected.")
                break
          
            receiver_socket.sendall(msg)
            
        except ConnectionResetError:
            print(f"[RELAY] Client {sender_addr[1]} forcefully closed the connection.")
            break
        except Exception as e:
            
            break
    
    
    shutdown_session_gracefully(sender_socket, receiver_socket)

def shutdown_session_gracefully(client_a_socket, client_b_socket):
    """Closes sockets and removes them from the global list safely."""
    with LOCK:
        try:
            client_a_addr = client_a_socket.getpeername()
            client_a_socket.shutdown(socket.SHUT_RDWR)
            client_a_socket.close()
            for i, (sock, addr) in enumerate(clients):
                if sock == client_a_socket:
                    del clients[i]
                    print(f"[CLEANUP] Closed and removed client A: {addr[1]}")
                    break
        except Exception:
            pass 

        try:
            client_b_addr = client_b_socket.getpeername()
            client_b_socket.shutdown(socket.SHUT_RDWR)
            client_b_socket.close()
            for i, (sock, addr) in enumerate(clients):
                if sock == client_b_socket:
                    del clients[i]
                    print(f"[CLEANUP] Closed and removed client B: {addr[1]}")
                    break
        except Exception:
            pass 
        
        print(f"[SESSION] Session terminated. Currently waiting for {len(clients)} client(s).")


def handle_session(client_a_tuple, client_b_tuple):
    """Manages the lifecycle and relay threads for a pair of clients."""
    client_a, addr_a = client_a_tuple
    client_b, addr_b = client_b_tuple
    
    print(f"\n--- NEW SESSION STARTED ---")
    print(f"Client A: {addr_a[1]}")
    print(f"Client B: {addr_b[1]}")
    
    # Start two separate relay threads: A -> B and B -> A
    relay_thread_ab = threading.Thread(
        target=relay_messages, 
        args=(client_a, client_b, addr_a, addr_b), 
        daemon=True
    )
    relay_thread_ab.start()
    
    relay_thread_ba = threading.Thread(
        target=relay_messages, 
        args=(client_b, client_a, addr_b, addr_a), 
        daemon=True
    )
    relay_thread_ba.start()
    
    # The session ends when either client disconnects, triggering shutdown_session_gracefully
    relay_thread_ab.join()
    relay_thread_ba.join()
    
    print(f"--- SESSION ENDED (Cleanly) ---\n")

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("127.0.0.1", 5000))
    except OSError as e:
        print(f"Error binding to port 5000: {e}. Check if the port is already in use.")
        sys.exit(1)
        
    server.listen(5)
    print("Server started on port 5000. Waiting for clients...")

    while True:
        try:
            client_socket, addr = server.accept()
            print(f"Client connected: {addr}")
            
            client_tuple = (client_socket, addr)
            
            with LOCK:
                clients.append(client_tuple)
                
                if len(clients) >= 2:
                    client_b = clients.pop()
                    client_a = clients.pop()
                    
                    threading.Thread(target=handle_session, args=(client_a, client_b), daemon=True).start()
                else:
                    print("Waiting for one more client to start a secure session...")
                    
        except KeyboardInterrupt:
            print("\nServer shutting down...")
            server.close()
            break
        except Exception as e:
            print(f"An unexpected error occurred in the server loop: {e}")
            
start_server()