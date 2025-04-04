import socket

# client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# client_socket.connect(('localhost', 8080))

# message = "Hello, Server!"

# client_socket.send(message.encode('utf-8'))

# response = client_socket.recv(1024).decode('utf-8')

# print(f"Received from server: {response}")

# client_socket.close()

def send_command(command):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 9090))

    client_socket.send(command.encode('utf-8'))

    response = client_socket.recv(1024).decode('utf-8')
    print(f"Server response: {response}")

    client_socket.close()

if __name__ == "__main__":
    send_command("HELLO")