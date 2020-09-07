package main

import (
  "flag"
  "log"

  "github.com/dlegs/bounty-hunter/subdomains"
)

var (
  useBountyTargets = flag.Bool("use_bounty_targets", true, "use all available bug bounty targets from https://github.com/arkadiyt/bounty-targets-data")
  targets = flag.String("targets", "", "manually specified targets")
)

func main() {
  flag.Parse()
  s := subdomains.New()
  subdomains, err := s.Enumerate([]string{"legg.io"})
  if err != nil {
    log.Fatalf("failed to enumerate subdomains: %v", err)
  }
  log.Println(subdomains)
}
