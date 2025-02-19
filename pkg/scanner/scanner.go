package scanner

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/grumpzsux/jxss/pkg/output"
)

// ProcessURL fetches the page at targetURL, extracts inline JavaScript from <script> tags,
// applies regex patterns to detect empty variable assignments, and checks whether the canary value is reflected.
// It returns a slice of output.ScanResult containing the reflection details.
func ProcessURL(targetURL, canary string, regexPatterns []string, client *http.Client) ([]output.ScanResult, error) {
	var results []output.ScanResult

	// Fetch the original page content.
	body, err := fetchURL(client, targetURL)
	if err != nil {
		return nil, err
	}

	// Extract inline JavaScript blocks using GoQuery.
	scripts, err := extractScripts(body)
	if err != nil {
		return nil, err
	}

	// Iterate over each script block and apply each regex pattern.
	for _, script := range scripts {
		for _, pattern := range regexPatterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				// Skip invalid regex patterns.
				continue
			}
			matches := re.FindAllStringSubmatch(script, -1)
			for _, match := range matches {
				if len(match) < 2 {
					continue
				}
				varName := match[1]
				// Append the variable name as a GET parameter with the canary value.
				injectedURL, err := appendParameter(targetURL, varName, canary)
				if err != nil {
					continue
				}
				// Fetch the page with the injected parameter.
				injectedBody, err := fetchURL(client, injectedURL)
				if err != nil {
					continue
				}
				// Construct a regex pattern to check if the canary is reflected.
				reflectPattern := fmt.Sprintf(`(?i)(?:var|let|const)\s+%s\s*=\s*(['"])%s\1`, regexp.QuoteMeta(varName), regexp.QuoteMeta(canary))
				if regexp.MustCompile(reflectPattern).MatchString(injectedBody) {
					results = append(results, output.ScanResult{
						URL:     injectedURL,
						VarName: varName,
						Status:  "reflected",
						Message: fmt.Sprintf("Canary '%s' reflected in variable '%s'", canary, varName),
					})
				}
			}
		}
	}

	return results, nil
}

// fetchURL retrieves the content of the specified URL using the provided HTTP client.
func fetchURL(client *http.Client, targetURL string) (string, error) {
	resp, err := client.Get(targetURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(bodyBytes), nil
}

// extractScripts uses GoQuery to extract the text content of all <script> tags from the provided HTML content.
func extractScripts(htmlContent string) ([]string, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		return nil, err
	}
	var scripts []string
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		scriptText := s.Text()
		if strings.TrimSpace(scriptText) != "" {
			scripts = append(scripts, scriptText)
		}
	})
	return scripts, nil
}

// appendParameter appends a GET parameter (key=value) to the given URL and returns the modified URL.
func appendParameter(rawURL, key, value string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := parsedURL.Query()
	q.Set(strings.ToLower(key), value)
	parsedURL.RawQuery = q.Encode()
	return parsedURL.String(), nil
}
