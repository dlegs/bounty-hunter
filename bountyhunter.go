package main

import (
  "bufio"
  "flag"
  "fmt"
  "log"
  "net"
  "net/http"
  "regexp"
  "strings"

  "github.com/CaliDog/certstream-go"
)

const (
  targetsURL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/wildcards.txt"
)

var (
  useBountyTargets = flag.Bool("use_bounty_targets", true, "use all available bug bounty targets from https://github.com/arkadiyt/bounty-targets-data")
  targets = flag.String("targets", "", "manually specified targets")
)

func main() {
  flag.Parse()

  // Fetch bug bounty targets as regexes.
  // TODO: Fetch every hour.
  regexes, err := fetchBountyTargets()
  if err != nil {
    log.Fatalf("failed to fetch bounty targets: %v", err)
  }

  // Kick off certstream.
  stream, errStream := certstream.CertStreamEventStream(false)
  for {
    select {
    case jq := <-stream:
      // Skip heartbeat messages.
      messageType, err := jq.String("message_type")
      if err != nil {
        log.Fatalf("failed to decode jq string: %v", err)
      }
      if messageType == "heartbeat" {
        break
      }

      // Parse domains from cert log.
      domains, err := jq.Array("data", "leaf_cert", "all_domains")
      if err != nil {
        log.Fatalf("failed to decode jq array: %v", err)
      }
      // Check if domains match bug bounty target regexes.
      // TODO: deal with dupes.
      for _, domain := range domains {
        for _, regex := range regexes {
          if regex.MatchString(domain.(string)) {
            if !resolves(domain.(string)) {
              continue
            }
            log.Printf("Found domain: %q", domain)
            // TODO: port scan etc.
          }
        }
      }

    case err := <-errStream:
      log.Print(err)
    }
  }
}

// fetchBountyTargets fetches wildcard domains of bug bounty targets from
// https://github.com/arkadiyt/bounty-targets-data and return a list of compiled
// regexes.
func fetchBountyTargets() ([]*regexp.Regexp, error) {
  res, err := http.Get(targetsURL)
  if err != nil {
    return nil, fmt.Errorf("failed to fetch targets: %v", err)
  }

  regexes := []*regexp.Regexp{}
  scanner := bufio.NewScanner(res.Body)
  for scanner.Scan() {
    // lint domain regex
    if strings.Contains(scanner.Text(), "zendesk") {
      continue
    }
    pattern := strings.ReplaceAll(scanner.Text(), "(", "")
    pattern = strings.ReplaceAll(scanner.Text(), ")", "")
    pattern = regexp.QuoteMeta(scanner.Text())
    pattern = strings.ReplaceAll(pattern, `\*`, ".*")
    pattern = fmt.Sprintf("^%s$", pattern)
    regex := regexp.MustCompile(pattern)
    regexes = append(regexes, regex)
  }
  return regexes, nil
}

func resolves(domain string) bool {
  _, err := net.ResolveIPAddr("ip4", domain)
  if err != nil {
    return false
  }
  return true
}
