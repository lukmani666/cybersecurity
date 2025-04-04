import socket

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 9090))
    server_socket.listen()

    print("Server is listening on port 9090...")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"connection from {client_address}")

        command = client_socket.recv(1024).decode('utf-8')
        print(f"Received command: {command}")

        if command == "HELLO":
            response = "Hello, Client"
        else:
            response = "Unknown command"
        
        client_socket.send(response.encode('utf-8'))
        client_socket.close()


if __name__ == "__main__":
    start_server()

