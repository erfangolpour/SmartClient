# SmartClient

SmartClient is a Python script that retrieves information about a web server given a URL. It can follow redirects, parse cookies, check for HTTP/2 support, and detect if the server is password-protected.

## Features

- Follow redirects with a configurable maximum number of redirects
- Parse and display cookies from the server's response
- Check if the server supports HTTP/2 (using ALPN and HTTP/2 upgrade)
- Detect if the server's response is password-protected
- Print the final response header and visited URLs

## Usage

```
python SmartClient.py <url>
```

Replace `<url>` with the URL you want to inspect.

## Example

```
$ python SmartClient.py www.google.com

[*] Sending request to http://www.google.com:80/...

---Request Begin---
GET / HTTP/1.1
Host: www.google.com
Connection: close
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
----Request End----

[*] HTTP request sent, awaiting response...

---Response Header Begin---
HTTP/1.1 302 Found
Location: https://www.google.com/?gws_rd=ssl
Cache-Control: private
Content-Type: text/html; charset=UTF-8
Content-Security-Policy-Report-Only: object-src 'none';base-uri 'self';script-src 'nonce-ZrreS9f5lgLI9UhUvT0vKQ' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp
Permissions-Policy: unload=()
Date: Thu, 16 May 2024 21:49:36 GMT
Server: gws
Content-Length: 231
X-XSS-Protection: 0
X-Frame-Options: SAMEORIGIN
Set-Cookie: AEC=AQTF6HxLnuWzxYdOf-U3RfwjeFhIRDzZRd9rkYakfBbXjej_Ouk60VAgYeA; expires=Tue, 12-Nov-2024 21:49:36 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax
Connection: close
----Response Header End----

[*] Redirecting to https://www.google.com:443/?gws_rd=ssl...
[*] Sending request to https://www.google.com:443/?gws_rd=ssl...

---Request Begin---
GET /?gws_rd=ssl HTTP/1.1
Host: www.google.com
Connection: close
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
----Request End----

[*] HTTP request sent, awaiting response...

---Response Header Begin---
HTTP/1.1 200 OK
Date: Thu, 16 May 2024 21:49:36 GMT
Expires: -1
Cache-Control: private, max-age=0
Content-Type: text/html; charset=UTF-8
Content-Security-Policy-Report-Only: object-src 'none';base-uri 'self';script-src 'nonce-IgyOIc6ZxzKFtSrQhdhw-Q' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp
Permissions-Policy: unload=()
P3P: CP="This is not a P3P policy! See g.co/p3phelp for more info."
Content-Encoding: br
Server: gws
Content-Length: 83445
X-XSS-Protection: 0
X-Frame-Options: SAMEORIGIN
Set-Cookie: AEC=AQTF6HwA5s7rl6PjZ9Ear11tKVucPtbhcp8d1nY2Ba5W2KXCtBrw04pqHw; expires=Tue, 12-Nov-2024 21:49:36 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax
Set-Cookie: NID=514=yWGLtEcxqjHZ8YDlWn4XDFXJioZM9TYLQsMBd4n4l6ary4ps2DHq8wpXCqivsP_CEWJZOmT16FwInbc3mjl9YRH2fKnFvsCnxs37VlmGJP-H0vc5NgPnHss0kbnARMorKO988FUHsLWb9N_Uai9DpzVBOjrjJX836B_nqEfL_6A; expires=Fri, 15-Nov-2024 21:49:36 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=none
Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
Connection: close
----Response Header End----


---------------Final Result---------------
Visited URIs:
    * http://www.google.com:80/
    * https://www.google.com:443/?gws_rd=ssl (final)
List of Cookies:
    * AEC
     - Value: AQTF6HwA5s7rl6PjZ9Ear11tKVucPtbhcp8d1nY2Ba5W2KXCtBrw04pqHw
     - Domain: .google.com
     - Expires on: Tue, 12-Nov-2024 21:49:36 GMT
     - Path: /
    * NID
     - Value: 514=yWGLtEcxqjHZ8YDlWn4XDFXJioZM9TYLQsMBd4n4l6ary4ps2DHq8wpXCqivsP_CEWJZOmT16FwInbc3mjl9YRH2fKnFvsCnxs37VlmGJP-H0vc5NgPnHss0kbnARMorKO988FUHsLWb9N_Uai9DpzVBOjrjJX836B_nqEfL_6A
     - Domain: .google.com
     - Expires on: Fri, 15-Nov-2024 21:49:36 GMT
     - Path: /
Supports HTTP/2: yes
Password-protected: no
------------------------------------------
```

## Code Structure

The code is organized into the following classes and functions:

### `URI` Class

Represents a URI and parses it into its components (protocol, host, port, path). It also checks if the URI is valid.

### `Socket` Class

A context manager for creating a socket connection. It handles both HTTP and HTTPS connections and supports ALPN protocols for HTTP/2.

### `WebServer` Class

Represents a web server and handles sending requests, parsing cookies, checking for HTTP/2 support, and detecting password-protected responses.

### `follow_redirects(uri, max_redirects, hops, cookies)`

A recursive function that follows redirects until the final response is received or `max_redirects` is reached. It keeps track of the visited URIs and cookies.

## Requirements

This script requires Python 3.6 or later and has no external dependencies.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the [GPLv3](LICENSE).
