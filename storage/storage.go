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

func New(dbName string) (*Client, error) {
  db, err := sql.Open("sqlite3", dbName)
  if err != nil {
    return nil, fmt.Errorf("failed opening db %q: %v", dbName, err)
  }

  if _, err := db.Exec("CREATE TABLE IF NOT EXISTS domains (domain TEXT PRIMARY KEY)"); err != nil {
    return nil, fmt.Errorf("failed creating domains table: %v", err)
  }

  if _, err := db.Exec("CREATE TABLE IF NOT EXISTS subdomains (subdomain TEXT PRIMARY KEY, domain TEXT, takeover BOOLEAN, FOREIGN KEY(domain) REFERENCES domains(domain))"); err != nil {
    return nil, fmt.Errorf("failed creating subdomains table: %v", err)
  }

  if _, err := db.Exec("CREATE TABLE IF NOT EXISTS ports (id INTEGER AUTO_INCREMENT PRIMARY KEY, port INTEGER, subdomain TEXT, protocol TEXT, service TEXT, product TEXT, version TEXT, FOREIGN KEY(subdomain) references subdomains(subdomain))"); err != nil {
    return nil, fmt.Errorf("failed creating ports table: %v", err)
  }

  return &Client{
    db: db,
  }, nil
}

func (c *Client) InsertDomain(domain string) error {
  statement, err := c.db.Prepare("INSERT OR IGNORE INTO domains (domain) VALUES (?)")
  if err != nil {
    return fmt.Errorf("failed to prepare insert statement: %v", err)
  }
  if _, err := statement.Exec(domain); err != nil {
    return fmt.Errorf("failed to execute insert statement: %v", err)
  }
  return nil
}

func (c *Client) InsertSubdomain(subdomain string, domain string) error {
  statement, err := c.db.Prepare("INSERT INTO subdomains (subdomain, domain) VALUES (?, ?)")
  if err != nil {
    return fmt.Errorf("failed to prepare insert statement: %v", err)
  }
  if _, err := statement.Exec(subdomain, domain); err != nil {
    return fmt.Errorf("failed to execute insert statement: %v", err)
  }
  return nil
}

func (c *Client) InsertPort(port int, subdomain string, protocol string, service string, product string, version string) error {
  statement, err := c.db.Prepare("INSERT INTO ports (port, subdomain, protocol, service, product, version) VALUES (?, ?, ?, ?, ?, ?)")
  if err != nil {
    return fmt.Errorf("failed to prepare insert statement: %v", err)
  }
  if _, err := statement.Exec(port, subdomain, protocol, service, product, version); err != nil {
    return fmt.Errorf("failed to execute insert statement: %v", err)
  }
  return nil
}

func (c *Client) SubdomainExists(subdomain string, domain string) (bool, error) {
  statement, err := c.db.Prepare("SELECT subdomain FROM subdomains WHERE subdomain = ? AND domain = ? LIMIT 1")
  if err != nil {
    return false, fmt.Errorf("failed to prepare exist statement: %v", err)
  }
  row := statement.QueryRow(subdomain, domain)
  var exists string
  err = row.Scan(&exists)
  if err == sql.ErrNoRows {
    return false, nil
  }
  if len(exists) == 0 {
    return false, fmt.Errorf("failed to exec query: %v", err)
  }
  return true, nil
}

func (c *Client) PortExists(port int, subdomain string) (bool, error) {
  statement, err := c.db.Prepare("SELECT subdomain FROM ports WHERE port = ? AND subdomain = ? LIMIT 1")
  if err != nil {
    return false, fmt.Errorf("failed to prepare exist statement: %v", err)
  }
  row := statement.QueryRow(port, subdomain)
  var exists string
  err = row.Scan(&exists)
  if err == sql.ErrNoRows {
    return false, nil
  }
  if len(exists) == 0 {
    return false, fmt.Errorf("failed to exec query: %v", err)
  }
  return true, nil
}
