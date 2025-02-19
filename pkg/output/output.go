package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// ScanResult represents a detection result.
type ScanResult struct {
	URL     string `json:"url" csv:"url" html:"url"`
	VarName string `json:"variable" csv:"variable" html:"variable"`
	Status  string `json:"status" csv:"status" html:"status"`
	Message string `json:"message" csv:"message" html:"message"`
}

// WriteOutput writes results to a file or stdout in the specified format.
func WriteOutput(results []ScanResult, format, filename string) error {
	var out io.Writer
	if filename != "" {
		f, err := os.Create(filename)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	} else {
		out = os.Stdout
	}

	switch strings.ToLower(format) {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	case "csv":
		w := csv.NewWriter(out)
		defer w.Flush()
		if err := w.Write([]string{"URL", "Variable", "Status", "Message"}); err != nil {
			return err
		}
		for _, r := range results {
			if err := w.Write([]string{r.URL, r.VarName, r.Status, r.Message}); err != nil {
				return err
			}
		}
		return nil
	case "html":
		// Simple HTML table output.
		fmt.Fprintln(out, "<html><head><title>jXSS Results</title></head><body>")
		fmt.Fprintln(out, "<table border='1'><tr><th>URL</th><th>Variable</th><th>Status</th><th>Message</th></tr>")
		for _, r := range results {
			fmt.Fprintf(out, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
				r.URL, r.VarName, r.Status, r.Message)
		}
		fmt.Fprintln(out, "</table></body></html>")
		return nil
	default:
		// Default plain text output.
		for _, r := range results {
			fmt.Fprintf(out, "[%s] %s - %s\n", r.Status, r.VarName, r.URL)
		}
		return nil
	}
}
