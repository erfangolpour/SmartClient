import socket
import ssl
import sys

def check_http2_support(host, port):
    try:
        # Create a socket connection to the host and port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)  # Set a timeout for the socket connection
        sock.connect((host, port))

        headers = {
            "Host": host,
            # "Connection": "Upgrade, HTTP2-Settings",
            "Connection": "Upgrade",
            "Upgrade": "h2c",
            "HTTP2-Settings": "AAMAAABkAAQCAAAAAAIAAAAA",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9"
        }

        query: str = f"GET / HTTP/1.1\r\n"
        for header, value in headers.items():
            query += f"{header}: {value}\r\n"
        query += "\r\n"

        # Send an HTTP/2 preface
        sock.sendall(query.encode())
        response = sock.recv(6000)

        # Check if the server supports HTTP/2
        print(response.decode("utf-8", "ignore").partition("\r\n\r\n")[0])
        if "HTTP/1.1 101 Switching Protocols" in response.decode("utf-8", "ignore"):
            return True

    except Exception as e:
        print(f"Error: {str(e)}")
        return False

if __name__ == "__main__":
    host = sys.argv[1]
    port = 80
    # port = int(sys.argv[2])

    if check_http2_support(host, port):
        print(f"\n{host}:{port} supports HTTP/2")
    else:
        print(f"\n{host}:{port} does not support HTTP/2")
