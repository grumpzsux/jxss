package httpclient

import (
	"bufio"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"context"

	"golang.org/x/net/proxy"
)

// ClientManager handles HTTP client creation with optional proxy rotation.
type ClientManager struct {
	proxies []string
	current int
}

// NewClientManager returns a new ClientManager instance.
func NewClientManager(proxies []string) *ClientManager {
	return &ClientManager{proxies: proxies, current: 0}
}

// GetNextClient returns an HTTP client, rotating proxies if available.
func (cm *ClientManager) GetNextClient() *http.Client {
	var client *http.Client
	if len(cm.proxies) > 0 {
		proxyURL := cm.proxies[cm.current]
		cm.current = (cm.current + 1) % len(cm.proxies)
		client = createHTTPClient(proxyURL)
	} else {
		client = createHTTPClient("")
	}
	return client
}

// createHTTPClient creates an HTTP client with optional proxy support.
func createHTTPClient(proxyStr string) *http.Client {
	transport := &http.Transport{}
	if proxyStr != "" {
		pu, err := url.Parse(proxyStr)
		if err == nil {
			if pu.Scheme == "socks5" || pu.Scheme == "socks5h" {
				dialer, err := proxy.FromURL(pu, proxy.Direct)
				if err == nil {
					transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
						return dialer.Dial(network, addr)
					}
				}
			} else {
				transport.Proxy = http.ProxyURL(pu)
			}
		}
	}
	return &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}
}

// ReadURLs reads URLs (one per line) from a file.
func ReadURLs(filename string) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var urls []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			urls = append(urls, line)
		}
	}
	return urls, scanner.Err()
}
