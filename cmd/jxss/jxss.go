package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	"github.com/grumpzsux/jxss/config"
	hc "github.com/grumpzsux/jxss/pkg/httpclient"
	out "github.com/grumpzsux/jxss/pkg/output"
	scan "github.com/grumpzsux/jxss/pkg/scanner"
)

// printBanner prints an ASCII banner when the tool starts.
func printBanner() {
	banner := `
     ______  ___  _________ _________
    |__\   \/  / /   _____//   _____/
    |  |\     /  \_____  \ \_____  \ 
    |  |/     \  /        \/        \
/\__|  /___/\  \/_______  /_______  / [v1.0]
\______|     \_/        \/        \/ 

jXSS - Find Reflected XSS in In-line JavaScript.
       | GRuMPzSux - www.grumpz.net |
`
	fmt.Println(banner)
}

func main() {
	printBanner()

	// Define and parse command-line flags.
	listFile := flag.String("list", "", "File containing list of URLs")
	canary := flag.String("canary", "", "Custom canary string")
	concurrency := flag.Int("concurrency", 5, "Number of concurrent workers")
	configFile := flag.String("config", "", "YAML configuration file")
	outputFormat := flag.String("format", "text", "Output format: text, json, csv, html")
	outputFile := flag.String("output", "", "File to write output")
	flag.Parse()

	// Validate required flags.
	if *listFile == "" || *canary == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -list <file> -canary <value> [options]\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Initialize structured logger.
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)

	// Load configuration.
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		logger.Fatalf("Error loading config file: %v", err)
	}

	// Merge custom regex patterns if provided in the config.
	// (For now, we'll assume our scanning logic uses a built-in or config-supplied list.)
	regexPatterns := []string{`(?i)(?:var|let|const)\s+([a-zA-Z0-9_$]+)\s*=\s*(['"])\2`}
	if len(cfg.Patterns) > 0 {
		regexPatterns = append(regexPatterns, cfg.Patterns...)
	}

	// Set up the HTTP client with proxy rotation.
	clientManager := hc.NewClientManager(cfg.Proxies)

	// Set up a rate limiter.
	rl := rate.NewLimiter(rate.Limit(cfg.RateLimit), int(cfg.RateLimit))

	// Load target URLs from the provided list file.
	urls, err := hc.ReadURLs(*listFile)
	if err != nil {
		logger.Fatalf("Error reading URLs: %v", err)
	}

	// Create channels for URLs and scan results.
	urlChan := make(chan string, len(urls))
	resultChan := make(chan out.ScanResult, len(urls)*5)

	// Feed URLs into the channel.
	for _, u := range urls {
		urlChan <- u
	}
	close(urlChan)

	// Worker pool for processing URLs.
	done := make(chan struct{})
	for i := 0; i < *concurrency; i++ {
		go func() {
			for targetURL := range urlChan {
				// Rate limit.
				if err := rl.Wait(nil); err != nil {
					logger.Errorf("Rate limiter error: %v", err)
					continue
				}
				// Get an HTTP client (with proxy rotation).
				client := clientManager.GetNextClient()
				// Process URL for scanning.
				results, err := scan.ProcessURL(targetURL, *canary, regexPatterns, client)
				if err != nil {
					logger.Errorf("Error processing URL %s: %v", targetURL, err)
					continue
				}
				// Send results to channel.
				for _, r := range results {
					resultChan <- r
					logger.WithFields(logrus.Fields{
						"url":      r.URL,
						"variable": r.VarName,
					}).Info("Reflection detected")
				}
			}
			done <- struct{}{}
		}()
	}

	// Wait for all workers to finish.
	for i := 0; i < *concurrency; i++ {
		<-done
	}
	close(resultChan)

	// Collect results.
	var finalResults []out.ScanResult
	for r := range resultChan {
		finalResults = append(finalResults, r)
	}

	// Write output in the specified format.
	if err := out.WriteOutput(finalResults, *outputFormat, *outputFile); err != nil {
		logger.Errorf("Error writing output: %v", err)
	}

	logger.Infof("Processing complete. Total URLs processed: %d", len(urls))
	// Optionally, add more metrics here.

	// Simulate a graceful shutdown delay.
	time.Sleep(1 * time.Second)
}
