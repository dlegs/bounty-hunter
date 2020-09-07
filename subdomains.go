package subdomains

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Client holds dependencies.
type Client struct {
	http     *http.Client
	crtshURL *url.URL
}

// cert holds cert data from crt.sh
type cert struct {
	IssuerCAID     int    `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	ID             int    `json:"id"`
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
}

// Enumerate parses certificate transparency logs from crt.sh to enumerate subdomains for a list of targets.
func (c *Client) Enumerate(domains []string) (map[string][]string, error) {
	subdomains := make(map[string][]string, len(domains))
	certsc := make(chan []cert)
	errc := make(chan error)
	for _, domain := range domains {
		go c.crtsh(domain, certsc, errc)
	}
	for _, domain := range domains {
		err := <-errc
		if err != nil {
			return nil, fmt.Errorf("failed to fetch certs: %v", err)
		}
		certs := <-certsc
		s := dedupe(certs)
		subdomains[domain] = s
	}

	return subdomains, nil
}

// crtsh queries crt.sh for a particular domain
func (c *Client) crtsh(domain string, certsc chan []cert, errc chan error) {
	u := *c.crtshURL
	u.Path = fmt.Sprintf("%s/?q=%s&output=json", u.Path, domain)
	resp, err := c.http.Get(u.String())
	if err != nil {
		errc <- fmt.Errorf("failed to make request: %v", err)
		return
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		errc <- fmt.Errorf("failed to read body: %v", err)
		return
	}
	certs := []cert{}
	if err = json.Unmarshal(body, &certs); err != nil {
		errc <- fmt.Errorf("failed parsing body JSON: %v", err)
		return
	}
	errc <- nil
	certsc <- certs
}

// dedupe de-duplicates domain names returned from crt.sh and returns the subdomain names as a slice of strings.
func dedupe(certs []cert) []string {
	subdomains := make([]string, 0, len(certs))
	seen := make(map[string]struct{}, len(certs))
	for _, cert := range certs {
		split := strings.Split(cert.NameValue, "\n")
		for _, subdomain := range split {
			if _, ok := seen[subdomain]; !ok {
				if resolve(subdomain) {
					seen[subdomain] = struct{}{}
					subdomains = append(subdomains, subdomain)
				}
			}
		}
	}
	return subdomains
}

// resolve checks to see if the subdomain resolves to an IPv4 addr.
func resolve(subdomain string) bool {
	_, err := net.ResolveIPAddr("ip4", subdomain)
	if err != nil {
		return false
	}
	return true
}
