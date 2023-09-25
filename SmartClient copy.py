import re
import socket
import ssl
from typing import Tuple

uri_pattern = re.compile(
    r'^(?:(?P<protocol>https?)://)?(?P<host>[^:/]+)(?::(?P<port>\d+))?((?P<path>.*?))?(?:[?#].*)?$',
    re.IGNORECASE
)

cookie_pattern = re.compile(
    r'Set-Cookie:\s(?P<name>\w+)=(?P<value>[^;]*)(?=.*?\sdomain=(?P<domain>[^;]+))?(?=.*?\sexpires=(?P<expires>[^;]+))?(?=.*?\spath=(?P<path>[^;]+))?.*',
    re.IGNORECASE
)

socket.setdefaulttimeout(10)


def create_ssl_socket(sock: socket.socket, host: str, protocols: list = ["http/1.1"]) -> ssl.SSLSocket:
    """Create an SSL socket.

    Args:
        sock (socket.socket): the socket to wrap
        host (str): the host name
        protocols (list, optional): the ALPN protocols. Defaults to ["http/1.1"].

    Returns:
        ssl.SSLSocket: the SSL socket
    """
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(protocols)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    return ctx.wrap_socket(sock, server_hostname=host)


def send_get_request(protocol: str, host: str, path: str, port: int = 80, connection: str = "close") -> Tuple[str, str]:
    """Send a GET request to the server.

    Args:
        protocol (str): the protocol to use
        host (str): the host name
        path (str): the path to the resource
        port (int, optional): the port number. Defaults to 80.
        connection (str, optional): the Connection type ("keep-alive" or "close"). Defaults to "close".

    Returns:
        (str, str): the response header and the response body
    """
    headers = {
        "Host": host,
        "Connection": connection,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
    }
    request = f"GET {path} HTTP/1.1\r\n"
    for header, value in headers.items():
        request += f"{header}: {value}\r\n"
    request += "\r\n"

    response = b""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if protocol == "https":
            sock = create_ssl_socket(sock, host)
        sock.connect((host, port))

        print("\n---Request Begin---")
        print(f"GET {path} HTTP/1.1")
        for header, value in headers.items():
            print(f"{header}: {value}")
        sock.sendall(request.encode())
        print("----Request End----")
        print("\n[*] HTTP request sent, awaiting response...")
        while True:
            data = sock.recv(1024)
            if not data:
                break
            response += data
    except socket.timeout:
        print("[-] Connection timeout.")
    except socket.gaierror:
        print("[-] The host name could not be resolved.")
    except ConnectionRefusedError:
        print("[-] Connection refused.")
    except socket.error as e:
        print(f"[x] Socket error: {e}")
    finally:
        sock.close()

    response = response.decode("utf-8", "ignore")
    if not response:
        return None, None

    header_body = response.split("\r\n\r\n")
    header = header_body[0]
    body = response.split("\r\n\r\n")[1] if len(header_body) > 1 else ""

    print("\n---Response Header Start---")
    print(header)
    print("----Response Header End----")
    print("\n---Response Body Start---")
    # print(body)
    print("[+] Size of response body:", len(body))
    print("[+] Number of lines in response body:", len(body.split("\n")))
    print("----Response Body End----")

    return header, body


def parse_cookies(header: str) -> list:
    """Parse cookies from the response header.

    Args:
        header (str): the response header

    Returns:
        list: a list of tuples of the form (cookie_name, cookie_domain, cookie_expires)
    """
    cookie_matches = cookie_pattern.finditer(header)
    return [(m.group("name"), m.group("domain"), m.group("expires"), m.group("path")) for m in cookie_matches]


def check_http2_support(host: str, port: int = 443) -> bool:
    """Check if the server supports HTTP/2.

    Args:
        host (str): the host name
        port (int, optional): the port number. Defaults to 443.

    Returns:
        bool: True if the server supports HTTP/2, False otherwise.
    """
    sock = create_ssl_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), host, ["spdy/3", "h2"])
    sock.connect((host, port))
    return sock.selected_alpn_protocol() == "h2"


def check_password_protected(response: str) -> bool:
    """Check if the response is password-protected.

    Args:
        response (str): the response header

    Returns:
        bool: True if the response is password-protected, False otherwise.
    """
    return "401 Unauthorized" in response


def follow_redirects(uri: str, max_redirects: int = 10, redirects: list = []) -> Tuple[str, str, str, list]:
    """Follow redirects until the final response is received or max_redirects is reached.

    Args:
        uri (str): the URI to send the request to
        max_redirects (int, optional): the maximum number of redirects to follow. Defaults to 10. Set to -1 to follow redirects until the final response.
        redirects (list, optional): a list of redirects. Defaults to [].

    Returns:
        (str, str, str, list): the final host, the response header, the response body, and the list of redirects
    """
    if max_redirects == 0:
        print("[x] Too many redirects.")
        return None, None, None, redirects

    uri_match = uri_pattern.match(uri)
    if not uri_match:
        print("[x] Invalid URI. See README.md for some examaple URIs.")
        sys.exit(1)

    protocol = uri_match.group("protocol") or "http"
    host = uri_match.group("host")
    port = int(uri_match.group("port")) if uri_match.group("port") else (443 if protocol == "https" else 80)
    path = uri_match.group("path") or "/"
    refined_uri = f"{protocol}://{host}:{port}{path}"
    print(f"[*] Sending request to {refined_uri}...")
    redirects.append(refined_uri)

    # send the request
    header, body = send_get_request(protocol, host, path, port)

    if not header:
        return None, None, None, redirects

    redirect_match = re.search(r'HTTP\/\d\.\d\s(?P<status>\d+)\s([^\r\n]*)', header)
    if redirect_match and redirect_match.group("status").startswith('3'):
        location_match = re.search(r'Location:\s(?P<uri>[^\n\r]*)', header)
        if location_match:
            new_url = location_match.group("uri")
            print(f"\n[*] Redirecting to {new_url}...")
            return follow_redirects(new_url, max_redirects - 1, redirects)

    return host, header, body, redirects


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python SmartClient.py <url>")
        sys.exit(1)
    input_uri = sys.argv[1]

    host, header, body, redirects = follow_redirects(input_uri, max_redirects=-1)

    if not header:
        print("[x] No response from the server.")
        sys.exit(1)

    print("\n\n---------------Final Output---------------")
    print("Redirects:")
    for redirect in redirects[:-1]:
        print(f"    * {redirect}")
    print(f"    * {redirects[-1]} (final)")

    try:
        http2_support = check_http2_support(host)
        print("Supports HTTP/2:", "yes" if http2_support else "no")
    except Exception as e:
        print("Failed to check HTTP/2 support:", e)

    cookies = parse_cookies(header)
    print("List of Cookies:")
    if not cookies:
        print("    No cookies")

    for name, domain, expires, path in cookies:
        print("    * Name:", name, end="")
        if expires:
            print(", Expires on:", expires, end="")
        if domain:
            print(", Domain:", domain, end="")
        if path:
            print(", Path:", path, end="")
        print()

    password_protected = check_password_protected(header)
    print("Password-protected:", "yes" if password_protected else "no")
    print("------------------------------------------")
