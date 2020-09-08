// Package portscan uses nmap to port scan targets.
package portscan

import (
  "context"
  "fmt"

  "github.com/Ullaakut/nmap"
)

func Scan(ctx context.Context, domain string) {
  scanner, err := nmap.NewScanner(
    nmap.WithTargets(domain),
    nmap.WithTimingTemplate(4),
    nmap.WithServiceInfo(),
    nmap.WithSkipHostDiscovery(),
    nmap.WithContext(ctx),
  )
  if err != nil {
    fmt.Println("failed to create nmap scanner: %v", err)
    return
  }

  result, warn, err := scanner.Run()
  if err != nil {
    fmt.Println("failed to run nmap scanner: %v", err)
  }
  if warn != nil {
    fmt.Println("failed to run nmap scanner: %v", err)
    return
  }

  for _, host := range result.Hosts {
    fmt.Printf("Host %q:\n", host.Hostnames[0].Name)
    for _, port := range host.Ports {
      fmt.Printf("\tPort %d/%s %s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name, port.Service.Version)
    }
    fmt.Printf("Elapsed: %3f seconds\n", result.Stats.Finished.Elapsed)
  }

}
