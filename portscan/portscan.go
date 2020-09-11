// Package portscan uses nmap to port scan targets.
package portscan

import (
  "context"
  "log"

  "github.com/Ullaakut/nmap"
  "github.com/dlegs/bounty-hunter/notify"
  "github.com/dlegs/bounty-hunter/storage"
)

// Client holds db and slack dependencies.
type Client struct {
  db *storage.Client
  slack *notify.Client
}

// New returns a new client.
func New(db *storage.Client, slack *notify.Client) *Client {
  return &Client{
    db: db,
    slack: slack,
  }
}

// Scan performs an nmap scan and sends found ports to the portsc channel.
func (c *Client) Scan(ctx context.Context, subdomain *storage.Subdomain, rescan bool, portsc chan []*storage.Port) {
  scanner, err := nmap.NewScanner(
    nmap.WithTargets(subdomain.Name),
    nmap.WithTimingTemplate(4),
    nmap.WithServiceInfo(),
    nmap.WithSkipHostDiscovery(),
    nmap.WithContext(ctx),
  )
  if err != nil {
    log.Fatalf("failed to create nmap scanner: %v", err)
  }

  result, warn, err := scanner.Run()
  if err != nil {
    log.Fatalf("failed to run nmap scanner: %v", err)
  }
  if warn != nil {
    log.Fatalf("failed to run nmap scanner: %v", err)
  }

  ports := []*storage.Port{}
  for _, host := range result.Hosts {
    log.Printf("Host: %q [%s]\n", host.Hostnames[0].Name, host.Addresses[0])
    for _, p := range host.Ports {
      log.Printf("\tPort %d/%s [%s] %s %s %s", p.ID, p.Protocol, p.State, p.Service.Name, p.Service.Product, p.Service.Version)
      if p.State.State != "open" {
        continue
      }
      port := &storage.Port{
        Number: int(p.ID),
        Subdomain: host.Hostnames[0].Name,
        Protocol: p.Protocol,
        Service: p.Service.Name,
        Product: p.Service.Product,
        Version: p.Service.Version,
      }
      ports = append(ports, port)
      exists, err := c.db.PortExists(port)
      if err != nil {
        log.Fatalf("failed to check if port %v exists: %v", port, err)
      }
      // Port is new, so insert into DB.
      if !exists {
        if err =c.db.InsertPort(port); err != nil {
          log.Fatalf("failed to insert port %v: %v", port, err)
        }
        // If we've seen the host already, alert that a new port opened up. 
        if rescan {
          if err = c.slack.NotifyPort(port); err != nil {
            log.Fatalf("failed to notify new port %v: %v", port, err)
          }
        }
        // Otherwise, do nothing since we'll send an alert for the whole host
        // later.
      }
    }
  }
  portsc <- ports
}
