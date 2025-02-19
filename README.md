<center><img src="https://github.com/user-attachments/assets/b04b1017-6a6e-4eb8-b3a3-6cd50148fc32" width="400" height="200"></center>

# jXSS

jXSS is a fast, flexible, and lightweight command-line tool written in Go for detecting reflected XSS vulnerabilities in inline JavaScript. jXSS scans web pages, extracts inline JavaScript code, detects empty variable assignments, and injects custom canary values to discover potential client-side vulnerabilities.

## Features

- **Inline JavaScript Scanning:** Automatically extracts and scans inline <script> tags using GoQuery.
- **Reflected XSS Detection:** Detects empty JavaScript variable assignments and injects a custom canary to identify reflected XSS.
- **Customizable Rules:** Supports custom regex patterns via YAML configuration to fine-tune detection.
- **Concurrent Processing:** Leverages Go's concurrency with a configurable worker pool and rate limiting to scan multiple URLs efficiently.
- **Proxy Support:** (Optional) Allows HTTP/SOCKS5 proxy configuration to bypass rate limits or IP-based restrictions.
- **Flexible Output Formats:** Supports output in text, JSON, CSV, and HTML formats for integration with other tools.
- **Structured Logging:** Uses Logrus for detailed logging and easy debugging.

## Installation
### Using Go
```bash
go install github.com/grumpzsux/jxss/cmd/jxss@latest
```
**Note:** If you face module proxy issues or want to test the latest release, you can bypass the module proxy:
```bash
GOPROXY=direct GOSUMDB=off go install -v github.com/grumpzsux/jxss/cmd/jxss@v0.1.2
```
The binary will be installed in your `$GOPATH/bin` (usually `$HOME/go/bin`).

### Building from Source
```bash
git clone https://github.com/grumpzsux/jxss.git
cd jxss
go build -o jxss ./cmd/jxss
```

## Usage
jXSS requires at least two flags: a file containing target URLs and a custom canary value. Below is the basic usage:
```bash
jxss -list <file> -canary <value> [options]
```

### Command-line Options
- `-list` **Required.** Path to a file containing a list of target URLs (one per line).
- `-canary` **Required.** Custom canary string to be injected into JavaScript variables.
- `-concurrency` Number of concurrent workers (default: 5).
- `-config` Path to a YAML configuration file containing custom regex patterns and proxy settings.
- `-format` Output format: text, json, csv, or html (default: text).
- `-output` File to save the output. If not specified, results are printed to stdout.

![image](https://github.com/user-attachments/assets/fbe8e757-5e8f-45ae-ba0a-ccc0f585aaaa)

## Examples
### Basic Scan
```bash
jxss -list targets.txt -canary Canary123
```
This command will scan each URL in `targets.txt`, inject the string `Canary123` into detected JavaScript variable assignments, and output any reflections.

### With Custom Configuration and JSON Output
```bash
jxss -list urls.txt -canary SecretToken -config config.yaml -format json -output results.json
```
This example uses a custom configuration file (`config.yaml`) to load additional regex patterns or proxy settings, outputs results in JSON format, and writes them to `results.json`.

## Configuration
jXSS supports custom configuration via a YAML file. This file can be used to specify:

- **Custom Regex Patterns:** Additional patterns for detecting JavaScript assignments.
- **Proxy Settings:** A list of proxies (HTTP, HTTPS, or SOCKS5) for rotating requests.
- **Rate Limit:** Configure the number of requests per second.

Example `config.yaml`:
```yaml
patterns:
  - '(?i)(?:var|let|const)\s+([a-zA-Z0-9_$]+)\s*=\s*([\'"])\2'
proxies:
  - "http://127.0.0.1:8080"
  - "socks5://127.0.0.1:1080"
rate_limit: 5
```
## Contributing
Contributions are welcome! Please follow these steps to contribute:

- Fork the Repository.
- Create a Feature Branch:
```bash
git checkout -b feature/your-feature-name
```
- Commit Your Changes:
Follow best practices and write clear commit messages.
- Push Your Branch:
```bash
git push origin feature/your-feature-name
```
- Open a Pull Request.

## Acknowledgments
- GoQuery for HTML parsing.
- Logrus for structured logging.
- ProjectDiscovery for inspiring similar tool structures.
- All contributors and the open-source community.



