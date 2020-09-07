package main

import (
  "flag"
  "fmt"

  "github.com/dlegs/bounty-hunter/subdomains"
)

var (
  useBountyTargets = flag.Bool("use_bounty_targets", true, "use all available bug bounty targets from https://github.com/arkadiyt/bounty-targets-data")
  targets = flag.String("targets", "", "manually specified targets")
)

func main() {
  flag.Init()
  s := subdomains.New()
  subdomains := s.Enumerate("legg.io")
  fmt.Println(subdomains)
}
