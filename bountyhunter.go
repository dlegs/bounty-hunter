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
  "github.com/dlegs/bounty-hunter/notify"
  "github.com/dlegs/bounty-hunter/portscan"
  "github.com/dlegs/bounty-hunter/storage"
  "github.com/dlegs/bounty-hunter/takeover"
)

const (
  targetsURL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/wildcards.txt"
)

var (
  useBountyTargets = flag.Bool("use_bounty_targets", true, "use all available bug bounty targets from https://github.com/arkadiyt/bounty-targets-data")
  targets = flag.String("targets", "", "manually specified targets")
  fingerprints = flag.String("fingerprints", "fingerprints.json", "JSON file containing subjack fingerprints")
  dbName = flag.String("db_name", "bountyhunter.db", "name of sqlite db file to use")
  slackEnv = flag.String("slack_env", "SLACK_TOKEN", "name of env variable holding slack token")
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

  // Instantiate dependencies.
  db, err := storage.New(*dbName)
  if err != nil {
    log.Fatalf("failed to create sqlite client: %v", err)
  }

  slack, err := notify.New(*slackEnv)
  if err != nil {
    log.Fatalf("failed to creat slack client: %v", err)
  }

  subjack, err := takeover.New(db, slack, *fingerprints)
  if err != nil {
    log.Fatalf("failed to create subjack client: %v", err)
  }

  nmap := portscan.New(db, slack)

  // Kick off certstream.
  stream, errStream := certstream.CertStreamEventStream(false)
  for {
    select {
    case jq := <-stream:
      // TODO: refactor
      go func() {
        // Skip heartbeat messages.
        messageType, err := jq.String("message_type")
        if err != nil {
          log.Fatalf("failed to decode jq string: %v", err)
        }
        if messageType == "heartbeat" {
          return
        }

        // Parse subdomains from cert log.
        subdomains, err := jq.ArrayOfStrings("data", "leaf_cert", "all_domains")
        if err != nil {
          log.Fatalf("failed to decode jq array: %v", err)
        }
        subdomains = dedupe(subdomains)
        // Check if subdomains match bug bounty target regexes.
        for _, sub := range subdomains {
          for _, regex := range regexes {
            if regex.MatchString(sub) {
              if !resolves(sub) {
                continue
              }
              // Parse tld+1 for base domain.
              domainName, err := publicsuffix.EffectiveTLDPlusOne(sub)
              if err != nil {
                log.Fatalf("failed to parse domain name: %v", err)
              }
              domain := &storage.Domain{
                Name: domainName,
              }
              // Insert domain into db for tracking.
              if err := db.InsertDomain(domain); err != nil {
                log.Fatalf("failed to insert domain %v into db: %v", domain, err)
              }
              subdomain := &storage.Subdomain{
                Name: sub,
                Domain: domain.Name,
              }
              // Check for existence of found subdomain.
              exists, err := db.SubdomainExists(subdomain)
              if err != nil {
                log.Fatalf("failed to check for existence of subdomain %v: %v", subdomain, err)
              }
              // If it doesn't exist, insert but wait to notify until scans are
              // done.
              if !exists {
                log.Printf("Found new subdomain: %q", subdomain.Name)
                if err := db.InsertSubdomain(subdomain); err != nil {
                  log.Fatalf("failed to insert subdomain into db: %v", err)
                }
              } else {
                log.Printf("Found existing subdomain: %q", subdomain)
              }
              // Run scanners regardless of whether subdomain is new.
              portsc := make(chan []*storage.Port, 1)
              takeoverc := make(chan string, 1)
              go nmap.Scan(ctx, subdomain, exists, portsc)
              go subjack.Identify(subdomain, exists, takeoverc)
              subdomain.Ports = <-portsc
              subdomain.Takeover = <-takeoverc
              // If the subdomain is new, now we notify with full scan results.
              if !exists {
                if err := slack.NotifySubdomain(subdomain); err != nil {
                  log.Fatalf("failed to notify new subdomain %v: %v", subdomain, err)
                }
              }
            }
          }
        }
      }()

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
      // skip zendesk.
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

// resolves performs a DNS A lookup on the domain.
func resolves(domain string) bool {
  _, err := net.ResolveIPAddr("ip4", domain)
  if err != nil {
    return false
  }
  return true
}

// dedupe removes duplicate strings from a string array.
func dedupe(subdomains []string) []string {
  seen := make(map[string]struct{}, len(subdomains))
  j := 0
  for _, subdomain := range subdomains {
    if _, ok := seen[subdomain]; ok {
      continue
    }
    seen[subdomain] = struct{}{}
    subdomains[j] = subdomain
    j++
  }
  return subdomains[:j]
}
