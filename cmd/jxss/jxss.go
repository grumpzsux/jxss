package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	"github.com/grumpzsux/jxss/config"
	hc "github.com/grumpzsux/jxss/pkg/httpclient"
	out "github.com/grumpzsux/jxss/pkg/output"
	scan "github.com/grumpzsux/jxss/pkg/scanner"
)

// printBanner prints the ASCII banner.
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

	// Define command-line flags.
	listFile := flag.String("list", "", "File containing list of URLs")
	canary := flag.String("canary", "", "Custom canary string")
	concurrency := flag.Int("concurrency", 5, "Number of concurrent workers")
	configFile := flag.String("config", "", "YAML configuration file")
	outputFormat := flag.String("format", "text", "Output format: text, json, csv, html")
	outputFile := flag.String("output", "", "File to write output")
	flag.Parse()

	if *listFile == "" || *canary == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -list <file> -canary <value> [options]\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Initialize structured logger.
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)

	// Load configuration. If no config file is provided, defaults are used.
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		logger.Fatalf("Error loading config: %v", err)
	}

	// Create a new rate limiter using the configured RateLimit.
	rl := rate.NewLimiter(rate.Limit(cfg.RateLimit), int(cfg.RateLimit))
	if rl == nil {
		logger.Fatal("Rate limiter is nil")
	}

	// Set up the HTTP client manager.
	clientManager := hc.NewClientManager(cfg.Proxies)

	// Read the target URLs.
	urls, err := hc.ReadURLs(*listFile)
	if err != nil {
		logger.Fatalf("Error reading URLs: %v", err)
	}

	// Create channels for URLs and results.
	urlChan := make(chan string, len(urls))
	resultChan := make(chan out.ScanResult, len(urls)*5)

	// Feed URLs into the channel.
	for _, u := range urls {
		urlChan <- u
	}
	close(urlChan)

	// Use a WaitGroup to wait for all worker goroutines.
	var wg sync.WaitGroup
	ctx := context.Background()

	// Launch worker goroutines.
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for targetURL := range urlChan {
				// Wait according to the rate limiter.
				if err := rl.Wait(ctx); err != nil {
					logger.Errorf("Rate limiter error: %v", err)
					continue
				}

				// Get an HTTP client (with proxy rotation, if configured).
				client := clientManager.GetNextClient()
				// Use a built-in regex pattern; you could extend this by merging with custom patterns.
				patterns := []string{`(?i)(?:var|let|const)\s+([a-zA-Z0-9_$]+)\s*=\s*(['"])\2`}
				results, err := scan.ProcessURL(targetURL, *canary, patterns, client)
				if err != nil {
					logger.Errorf("Error processing URL %s: %v", targetURL, err)
					continue
				}
				for _, r := range results {
					resultChan <- r
					logger.WithFields(logrus.Fields{
						"url":      r.URL,
						"variable": r.VarName,
					}).Info("Reflection detected")
				}
			}
		}()
	}

	// Wait for all workers to complete.
	wg.Wait()
	close(resultChan)

	// Collect all results.
	var finalResults []out.ScanResult
	for r := range resultChan {
		finalResults = append(finalResults, r)
	}

	// Write the output in the specified format.
	if err := out.WriteOutput(finalResults, *outputFormat, *outputFile); err != nil {
		logger.Errorf("Error writing output: %v", err)
	}

	logger.Infof("Processing complete. Total URLs processed: %d", len(urls))
	// Graceful shutdown delay.
	time.Sleep(1 * time.Second)
}
