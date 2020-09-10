// Package takeover uses subjack to check for subdomain takeovers.
package takeover

import (
  "fmt"
  "encoding/json"
  "io/ioutil"
  "strings"

  "github.com/haccer/subjack/subjack"
  "github.com/dlegs/bounty-hunter/notify"
  "github.com/dlegs/bounty-hunter/storage"
)

type Client struct {
  db *storage.Client
  slack *notify.Client
  fingerprints []subjack.Fingerprints
}

func New(db *storage.Client, slack *notify.Client, fingerprintsFile string) (*Client, error) {
  var fingerprints []subjack.Fingerprints
  config, err := ioutil.ReadFile(fingerprintsFile)
  if err != nil {
    return nil, fmt.Errorf("failed to read subjack fingerprints file: %v", err)
  }
  if err = json.Unmarshal(config, &fingerprints); err != nil {
    return nil, fmt.Errorf("failed to parse fingerprints json: %v")
  }
  return &Client{
    db: db,
    slack: slack,
    fingerprints: fingerprints,
  }, nil
}

func(c *Client) Identify(subdomain *storage.Subdomain, rescan bool, takeoverc chan string) {
  service := subjack.Identify(subdomain.Name, false, false, 10, c.fingerprints)
  if service != "" {
    subdomain.Takeover = strings.ToLower(service)
    // If subdomain exists, notify that a new takeover has been found.
    if rescan {
      if err := c.slack.NotifyTakeover(subdomain); err != nil {
        return
      }
    }
  } else {
    subdomain.Takeover = ""
  }
  if err := c.db.InsertSubdomain(subdomain); err != nil {
    return
  }
  takeoverc <- strings.ToLower(service)
}
