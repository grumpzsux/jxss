package scanner

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

// ProcessURL fetches the page at targetURL, scans inline JavaScript, and checks for reflection of the canary.
// It uses both a built-in regex pattern and can be extended to use a JavaScript parser if needed.
func ProcessURL(targetURL, canary string, regexPatterns []string, client *http.Client) ([]struct {
	URL     string
	VarName string
	Status  string
	Message string
}, error) {
	var results []struct {
		URL     string
		VarName string
		Status  string
		Message string
	}

	// Fetch the original page.
	body, err := fetchURL(client, targetURL)
	if err != nil {
		return nil, err
	}

	// Use GoQuery to extract inline JavaScript from <script> tags.
	scripts, err := extractScripts(body)
	if err != nil {
		return nil, err
	}

	// For each script block, look for empty variable assignments.
	for _, script := range scripts {
		for _, pattern := range regexPatterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
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
				// Check for reflection.
				reflectPattern := fmt.Sprintf(`(?i)(?:var|let|const)\s+%s\s*=\s*(['"])%s\1`, regexp.QuoteMeta(varName), regexp.QuoteMeta(canary))
				if regexp.MustCompile(reflectPattern).MatchString(injectedBody) {
					results = append(results, struct {
						URL     string
						VarName string
						Status  string
						Message string
					}{
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

// fetchURL retrieves the content at the given URL using the provided client.
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

// extractScripts uses GoQuery to extract the text from all <script> tags.
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

// appendParameter adds a GET parameter to the URL.
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
