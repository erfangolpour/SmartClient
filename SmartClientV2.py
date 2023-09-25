import re
import socket
import ssl
from typing import Tuple, List, Dict, Optional

uri_pattern: re.Pattern = re.compile(
    r'^(?:(?P<protocol>https?)://)?(?P<host>[^:/]+)(?::(?P<port>\d+))?((?P<path>.*?))?$',
    re.IGNORECASE
)

cookie_pattern: re.Pattern = re.compile(
    r'Set-Cookie:\s(?P<name>[^=]+)=(?P<value>[^;]*)(?=.*?\sdomain=(?P<domain>[^;]+))?(?=.*?\sexpires=(?P<expires>[^;]+))?(?=.*?\spath=(?P<path>[^;]+))?.*',
    re.IGNORECASE
)


def banner(title: str, msg: str) -> None:
    """Prints a banner.

    Args:
        title (str): the title of the banner
        msg (str): the message to print
    """
    print(f"\n---{title} Begin---")
    print(msg)
    print(f"----{title} End----\n")


def log(msg: str, type: str = "info") -> None:
    """Prints a log message.

    Args:
        msg (str): the message to print
        type (str, optional): the type of message. Defaults to "info".
    """
    if type == "success":
        print(f"[+] {msg}")
    elif type == "warning":
        print(f"[!] {msg}")
    elif type == "error":
        print(f"[x] {msg}")
    elif type == "info":
        print(f"[*] {msg}")
    else:
        print(f"[?] {msg}")


class URI:
    def __init__(self, raw_uri: str) -> None:
        """Object to represent a URI.

        Args:
            raw_uri (str): the raw URI
        """
        uri_match = uri_pattern.match(raw_uri)
        if not uri_match:
            self.is_valid: bool = False
            return
        self.is_valid: bool = True
        self.protocol: str = uri_match.group("protocol") or "http"
        self.host: str = uri_match.group("host")
        self.port: int = int(uri_match.group("port")) if uri_match.group(
            "port") else (443 if self.protocol == "https" else 80)
        self.path: str = uri_match.group("path") or "/"

    def __str__(self) -> str:
        return f"{self.protocol}://{self.host}:{self.port}{self.path}"


class Socket:
    def __init__(self, uri: URI, alpn_proto: Optional[List[str]] = ["http/1.1"], timeout: Optional[int] = 10) -> None:
        """Context manager for creating a socket connection.

        Args:
            webServer (WebServer): the web server
            alpn_proto (List[str], optional): the ALPN protocols. Defaults to ["http/1.1"].
            timeout (int, optional): the timeout in seconds. Defaults to 10.
        """
        self.uri: URI = uri
        self.alpn_proto: List[str] = alpn_proto
        self.timeout: int = timeout

    def __enter__(self) -> socket.socket:
        self.sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        if self.uri.protocol == "https":
            ctx: ssl.SSLContext = ssl.create_default_context()
            ctx.set_alpn_protocols(self.alpn_proto)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            self.sock: ssl.SSLSocket = ctx.wrap_socket(self.sock, server_hostname=self.uri.host)

        self.sock.connect((self.uri.host, self.uri.port))
        return self.sock

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.sock.close()


class WebServer:
    def __init__(self, uri: URI) -> None:
        """Object to represent a web server.

        Args:
            uri (URI): the URI
        """
        self.uri: URI = uri
        self.header: str = ""
        self.succeeded: bool = False

    def request(self, connection: Optional[str] = "close", verbose: bool = False) -> None:
        """Send a request to the server.

        Args:
            connection (str, optional): the connection type ("close", "keep-alive", or "upgrade"). Defaults to "close".
            verbose (bool, optional): whether to print the request. Defaults to False.
        """
        headers: Dict[str, str] = {
            "Host": self.uri.host,
            "Connection": connection,
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9"
        }
        if connection == "upgrade":
            headers.update({
                "Upgrade": "h2c",
                "HTTP2-Settings": "AAMAAABkAAQCAAAAAAIAAAAA",
            })

        query: str = f"GET {self.uri.path} HTTP/1.1\r\n"
        for header, value in headers.items():
            query += f"{header}: {value}\r\n"
        query += "\r\n"

        response: bytes = b''
        try:
            with Socket(self.uri) as sock:
                if verbose:
                    log(f"Sending request to {self.uri}...")
                    banner("Request", query.replace("\r\n", "\n").strip())
                sock.sendall(query.encode())
                if verbose:
                    log("HTTP request sent, awaiting response...")
                while b"\r\n\r\n" not in response:
                    response += sock.recv(1024)
        except socket.gaierror:
            log(f"Failed to connect to {self.uri.host}:{self.uri.port}: The host name could not be resolved.", "error")
        except ConnectionRefusedError:
            log(f"Connection refused by {self.uri.host}:{self.uri.port}", "error")
        except socket.timeout:
            log("Timed out while receiving data.", "warning")
        except socket.error as e:
            log(f"Socket error: {e}", "error")

        response = response.decode("utf-8", "ignore")
        self.header = response.split("\r\n\r\n")[0]

        if self.header:
            self.succeeded = True
            if verbose:
                banner("Response Header", self.header)

    def parse_cookies(self) -> Dict[str, Tuple[str, str, str]]:
        """Parse cookies from the response header.

        Returns:
            Dict[str, Tuple[str, str, str]]: the cookies in the response header
        """
        cookie_matches: List[re.Match] = cookie_pattern.finditer(self.header)
        return {m.group("name"): (m.group("domain"), m.group("expires"), m.group("path")) for m in cookie_matches}

    def is_http2_supported(self) -> bool:
        """Check if the server supports HTTP/2.

        Returns:
            bool: True if the server supports HTTP/2, False otherwise.
        """
        if self.uri.protocol != "https":
            self.request(connection="upgrade")
            return "101 Switching Protocols" in self.header

        try:
            with Socket(self.uri, alpn_proto=["h2", "spdy/3"]) as sock:
                return sock.selected_alpn_protocol() in {"h2", "spdy/3"}
        except ssl.SSLError:
            log("Failed to connect to the server using HTTP/2.", "warning")
            return False
        except Exception as e:
            log(f"Failed to connect to the server using HTTP/2: {e}", "warning")
            return None

    def is_password_protected(self) -> bool:
        """Check if the response is password-protected.

        Returns:
            bool: True if the response is password-protected, False otherwise.
        """
        return "401 Unauthorized" in self.header


def follow_redirects(uri: URI, max_redirects: Optional[int] = 10, hops: Optional[List[URI]] = [], cookies: Optional[Dict[str, Tuple[str, str, str]]] = {}) -> Tuple[WebServer, List[URI], Dict[str, Tuple[str, str, str]]]:
    """Follow redirects until the final response is received or max_redirects is reached.

    Args:
        uri (URI): the URI
        max_redirects (int, optional): the maximum number of redirects to follow. Defaults to 10.
        hops (List[URI], optional): the list of visited URIs. Defaults to [].
        cookies (Dict[str, Tuple[str, str, str]], optional): the cookies. Defaults to {}.

    Returns:
        Tuple[Response, List[URI], Dict[str, Tuple[str, str, str]]]: the final response, the list of redirects, and the cookies
    """
    if max_redirects == 0:
        log("Too many redirects.", "error")
        return None, None, hops

    if not uri.is_valid:
        log("Invalid URI. See README.md for some examaple URIs.", "error")
        sys.exit(1)

    # send the request
    web_server: WebServer = WebServer(uri)
    web_server.request(verbose=True)
    cookies.update(web_server.parse_cookies())
    hops.append(uri)

    redirect_match = re.search(r'HTTP\/\d\.\d\s(?P<status>\d+)\s([^\r\n]*)', web_server.header)
    if redirect_match and redirect_match.group("status").startswith('3'):
        if location_match := re.search(r'Location:\s(?P<uri>[^\n\r]*)', web_server.header):
            new_url = URI(location_match.group("uri"))
            log(f"Redirecting to {new_url}...")
            return follow_redirects(new_url, max_redirects - 1, hops, cookies)

    return web_server, hops, cookies


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python SmartClient.py <url>")
        sys.exit(1)
    input_uri = URI(sys.argv[1])

    web_server, hops, cookies = follow_redirects(input_uri, max_redirects=-1)

    if not web_server.succeeded:
        log("No response from the server.", "error")
        sys.exit(1)

    print("\n---------------Final Result---------------")
    print("Visited URIs:")
    for redirect in hops[:-1]:
        print(f"    * {redirect}")
    print(f"    * {hops[-1]} (final)")

    if (http2_support := web_server.is_http2_supported()) is not None:
        print("Supports HTTP/2:", "yes" if http2_support else "no")
    else:
        log("Failed to check if the server supports HTTP/2.", "warning")

    cookies = web_server.parse_cookies()
    print("List of Cookies:")
    if not cookies:
        print("    No cookies found.")

    for name, value in cookies.items():
        print("    * Name:", name, end="")
        if value[0]:
            print(", Domain:", value[0], end="")
        if value[1]:
            print(", Expires on:", value[1], end="")
        if value[2]:
            print(", Path:", value[2], end="")
        print()

    print("Password-protected:", "yes" if web_server.is_password_protected() else "no")
    print("------------------------------------------")
