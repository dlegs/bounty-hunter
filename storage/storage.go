// Package storage provides intofaces into an sqlite database for storing
// found subdomains.
package storage

import (
  "fmt"
  "database/sql"

  _ "github.com/mattn/go-sqlite3"
)

type Client struct {
  db *sql.DB
}

type Domain struct {
  Name string
  Subdomains []Subdomain
}

type Subdomain struct {
  Name string
  Domain string
  Ports []*Port
  Takeover string
}

type Port struct {
  Number int
  Subdomain string
  Protocol string
  Service string
  Product string
  Version string
}

func New(dbName string) (*Client, error) {
  db, err := sql.Open("sqlite3", dbName)
  if err != nil {
    return nil, fmt.Errorf("failed opening db %q: %v", dbName, err)
  }

  if _, err := db.Exec("CREATE TABLE IF NOT EXISTS domains (domain TEXT PRIMARY KEY)"); err != nil {
    return nil, fmt.Errorf("failed creating domains table: %v", err)
  }

  if _, err := db.Exec("CREATE TABLE IF NOT EXISTS subdomains (subdomain TEXT PRIMARY KEY, domain TEXT, takeover TEXT, FOREIGN KEY(domain) REFERENCES domains(domain))"); err != nil {
    return nil, fmt.Errorf("failed creating subdomains table: %v", err)
  }

  if _, err := db.Exec("CREATE TABLE IF NOT EXISTS ports (id INTEGER AUTO_INCREMENT PRIMARY KEY, port INTEGER, subdomain TEXT, protocol TEXT, service TEXT, product TEXT, version TEXT, FOREIGN KEY(subdomain) references subdomains(subdomain))"); err != nil {
    return nil, fmt.Errorf("failed creating ports table: %v", err)
  }

  return &Client{
    db: db,
  }, nil
}

func (c *Client) InsertDomain(domain *Domain) error {
  statement, err := c.db.Prepare("INSERT OR IGNORE INTO domains (domain) VALUES (?)")
  if err != nil {
    return fmt.Errorf("failed to prepare insert statement: %v", err)
  }
  if _, err := statement.Exec(domain.Name); err != nil {
    return fmt.Errorf("failed to execute insert statement: %v", err)
  }
  return nil
}

func (c *Client) InsertSubdomain(subdomain *Subdomain) error {
  statement, err := c.db.Prepare("INSERT OR IGNORE INTO subdomains (subdomain, domain, takeover) VALUES (?, ?, ?)")
  if err != nil {
    return fmt.Errorf("failed to prepare insert statement: %v", err)
  }
  if _, err := statement.Exec(subdomain.Name, subdomain.Domain, subdomain.Takeover); err != nil {
    return fmt.Errorf("failed to execute insert statement: %v", err)
  }
  return nil
}

func (c *Client) InsertPort(port *Port) error {
  statement, err := c.db.Prepare("INSERT INTO ports (port, subdomain, protocol, service, product, version) VALUES (?, ?, ?, ?, ?, ?)")
  if err != nil {
    return fmt.Errorf("failed to prepare insert statement: %v", err)
  }
  if _, err := statement.Exec(port.Number, port.Subdomain, port.Protocol, port.Service, port.Product, port.Version); err != nil {
    return fmt.Errorf("failed to execute insert statement: %v", err)
  }
  return nil
}

func (c *Client) SubdomainExists(subdomain *Subdomain) (bool, error) {
  statement, err := c.db.Prepare("SELECT subdomain FROM subdomains WHERE subdomain = ? AND domain = ? LIMIT 1")
  if err != nil {
    return false, fmt.Errorf("failed to prepare exist statement: %v", err)
  }
  var exists string
  err = statement.QueryRow(subdomain.Name, subdomain.Domain).Scan(&exists)
  if err == sql.ErrNoRows {
    return false, nil
  }
  if len(exists) == 0 {
    return false, fmt.Errorf("failed to exec query: %v", err)
  }
  return true, nil
}

func (c *Client) PortExists(port *Port) (bool, error) {
  statement, err := c.db.Prepare("SELECT subdomain FROM ports WHERE port = ? AND subdomain = ?  AND protocol = ? AND service = ? AND product = ? AND VERSION = ? LIMIT 1")
  if err != nil {
    return false, fmt.Errorf("failed to prepare exist statement: %v", err)
  }
  var exists string
  err = statement.QueryRow(port.Number, port.Subdomain, port.Protocol, port.Service, port.Product, port.Version).Scan(&exists)
  if err == sql.ErrNoRows {
    return false, nil
  }
  if len(exists) == 0 {
    return false, fmt.Errorf("failed to exec query: %v", err)
  }
  return true, nil
}
