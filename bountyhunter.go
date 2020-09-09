package main

import (
  "context"
  "bufio"
  "flag"
  "fmt"
  "log"
  "net"
  "net/http"
  "regexp"
  "strings"

  "golang.org/x/net/publicsuffix"
  "github.com/CaliDog/certstream-go"
  "github.com/dlegs/bounty-hunter/portscan"
  "github.com/dlegs/bounty-hunter/takeover"
  "github.com/dlegs/bounty-hunter/storage"
)

const (
  targetsURL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/wildcards.txt"
)

var (
  useBountyTargets = flag.Bool("use_bounty_targets", true, "use all available bug bounty targets from https://github.com/arkadiyt/bounty-targets-data")
  targets = flag.String("targets", "", "manually specified targets")
  fingerprints = flag.String("fingerprints", "fingerprints.json", "JSON file containing subjack fingerprints")
  dbName = flag.String("db_name", "bountyhunter.db", "name of sqlite db file to use")
)

func main() {
  flag.Parse()
  ctx := context.Background()

  // Fetch bug bounty targets as regexes.
  // TODO: Fetch every hour.
  regexes, err := fetchBountyTargets()
  if err != nil {
    log.Fatalf("failed to fetch bounty targets: %v", err)
  }

  subjack, err := takeover.New(*fingerprints)
  if err != nil {
    log.Fatalf("failed to create subjack client: %v", err)
  }

  db, err := storage.New(*dbName)
  if err != nil {
    log.Fatalf("failed to create sqlite client: %v", err)
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

      // Parse subdomains from cert log.
      subdomains, err := jq.Array("data", "leaf_cert", "all_domains")
      if err != nil {
        log.Fatalf("failed to decode jq array: %v", err)
      }
      // Check if domains match bug bounty target regexes.
      // TODO: deal with dupes.
      for _, subdomain := range subdomains {
        for _, regex := range regexes {
          if regex.MatchString(subdomain.(string)) {
            if !resolves(subdomain.(string)) {
              continue
            }
            domain, err := publicsuffix.EffectiveTLDPlusOne(subdomain.(string))
            if err != nil {
              log.Fatalf("failed to parse domain: %v", err)
            }
            if err := db.InsertDomain(domain); err != nil {
              log.Fatalf("failed to insert domain into db: %v", err)
            }
            exists, err := db.SubdomainExists(subdomain.(string), domain)
            if err != nil {
              log.Fatalf("failed to check for existence of subdomain %q: %v", subdomain.(string), err)
            }
            if !exists {
              log.Printf("Found new subdomain: %q", subdomain.(string))
              if err := db.InsertSubdomain(subdomain.(string), domain); err != nil {
                log.Fatalf("failed to insert subdomain into db: %v", err)
              }
            } else {
              log.Printf("Found existing subdomain: %q", subdomain.(string))
            }
            go portscan.Scan(ctx, subdomain.(string))
            go subjack.Identify(subdomain.(string))
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
      //continue
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
