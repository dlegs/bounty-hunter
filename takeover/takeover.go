// Package takeover uses subjack to check for subdomain takeovers.
package takeover

import (
  "fmt"
  "encoding/json"
  "io/ioutil"
  "strings"

  "github.com/haccer/subjack/subjack"
)

type Client struct {
  Fingerprints []subjack.Fingerprints
}

func New(fingerprintsFile string) (*Client, error) {
  var fingerprints []subjack.Fingerprints
  config, err := ioutil.ReadFile(fingerprintsFile)
  if err != nil {
    return nil, fmt.Errorf("failed to read subjack fingerprints file: %v", err)
  }
  if err = json.Unmarshal(config, &fingerprints); err != nil {
    return nil, fmt.Errorf("failed to parse fingerprints json: %v")
  }
  return &Client{
    Fingerprints: fingerprints,
  }, nil
}

func(c *Client) Identify(subdomain string) {
  service := subjack.Identify(subdomain, false, false, 10, c.Fingerprints)
  if service != "" {
    service = strings.ToLower(service)
    fmt.Printf("%s is pointing to a vulnerable %s service.\n", subdomain, service)
  }
}
