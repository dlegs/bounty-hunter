package main

import (
  "bufio"
  "flag"
  "fmt"
  "log"
  "net/http"
  "time"

  "github.com/dlegs/bounty-hunter/subdomains"
)

const (
  targetsURL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/wildcards.txt"
)

var (
  useBountyTargets = flag.Bool("use_bounty_targets", true, "use all available bug bounty targets from https://github.com/arkadiyt/bounty-targets-data")
  targets = flag.String("targets", "", "manually specified targets")
)

func main() {
  start := time.Now()
  flag.Parse()
  targets, err := fetchBountyTargets()
  if err != nil {
    log.Fatalf("failed to fetch bounty targets: %v", err)
  }
  s := subdomains.New()
  subdomains, err := s.Enumerate(targets)
  if err != nil {
    log.Fatalf("failed to enumerate subdomains: %v", err)
  }
  log.Println(subdomains)
  log.Println(time.Since(start))
}

func fetchBountyTargets() ([]string, error) {
  res, err := http.Get(targetsURL)
  if err != nil {
    return nil, fmt.Errorf("failed to fetch targets: %v", err)
  }

  targets := []string{}
  scanner := bufio.NewScanner(res.Body)
  for scanner.Scan() {
    targets = append(targets, scanner.Text())
  }
  return targets, nil
}
