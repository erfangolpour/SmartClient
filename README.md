Title: Smart Client
Author: Erfan Golpour V00991341
Date: September 20, 2023

Usage: python3 SmartClient.py <URI>
Note: URI is parsed with regex and works with many different formats. See below:
A few examples of valid URIs:
    example.com
    www.example.com
    www.example.com/
    www.example.com/path
    www.example.com/path/file
    www.example.com:8080
    www.example.com:8080/path
    www.example.com:8080/path/file
    http://www.example.com
    http://www.example.com/path
    http://www.example.com/path/file
    http://www.example.com:8080/path/file?query
    http://www.example.com:8080/path/file/?query
    http://www.example.com:8080/path/file?query#fragment
    http://www.example.com:8080/path/file/?query#fragment