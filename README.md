# jXSS

jXSS is bug bounty tool designed to find reflected XSS vulnerabilities in inline JavaScript code. It scans web pages for empty JavaScript variable assignments, injects a canary value via GET parameters, and checks if the canary is reflected in the page.

## Features

- **HTML Parsing:** Uses [GoQuery](https://github.com/PuerkitoBio/goquery) to extract inline JavaScript.
- **Variable Detection:** Uses regex (and can be extended with JavaScript parser logic) to detect variable assignments.
- **Customizable Patterns:** Optionally load custom regex patterns via a YAML configuration file.
- **Concurrent Processing:** Supports concurrent scanning with rate limiting.
- **Proxy Support:** (Optional) Supports using proxies to avoid IP blocking.
- **Multiple Output Formats:** Outputs results in text, JSON, CSV, or HTML formats.

## Project Structure

