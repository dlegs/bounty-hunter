// Package notify uses Slack to notify when a new artifact is found.
package notify

import (
  "fmt"
  "os"

  "github.com/slack-go/slack"
  "github.com/dlegs/bounty-hunter/storage"
)

// Client holds the slack client dependency and channels the bot is part of.
type Client struct {
  slack *slack.Client
  channels []string
}

// New returns a new authenticated slack client.
func New(slackEnv string) (*Client, error) {
  token := os.Getenv(slackEnv)
  if token == "" {
    return nil, fmt.Errorf("slack token env var is not set")
  }
  api := slack.New(token)

  test, err := api.AuthTest()
  if err != nil {
    return nil, fmt.Errorf("failed to perform slack auth test: %v", err)
  }
  if test.User == "" {
    return nil, fmt.Errorf("failed to authenticate to slack: %v", err)
  }

  channels, _, err := api.GetConversations(&slack.GetConversationsParameters{})
  if err != nil {
    return nil, fmt.Errorf("failed to get list of slack channels: %v", err)
  }
  channelIDs := []string{}
  for _, channel := range channels {
    if !channel.IsMember {
      continue
    }
    channelIDs = append(channelIDs, channel.GroupConversation.Conversation.ID)
  }
  if len(channelIDs) == 0 {
    return nil, fmt.Errorf("slack bot is not added to any channels")
  }

  return &Client{
    slack: slack.New(token),
    channels: channelIDs,
  }, nil
}

// NotifyPort sends a slack message to available channels that a port has been
// new port has opened up on an existing subdomain.
func(c *Client) NotifyPort(port *storage.Port) error {
  msg := fmt.Sprintf("Newly opened port on host: %s\n\tPort: %d/%s %s %s %s", port.Subdomain, port.Number, port.Protocol, port.Service, port.Product, port.Version)
  return c.sendMsg(msg)
}

// NotifyTakeover sends a slack message to available channels that a subdomain
// takeover has been found on a subdomain.
func (c *Client) NotifyTakeover(subdomain *storage.Subdomain) error {
  msg := fmt.Sprintf("New subdomain takeover on host: %s\n\tService: %s", subdomain.Name, subdomain.Takeover)
  return c.sendMsg(msg)
}

// NotifySubdomain sends a slack message to available channels that a subdomain
// has been found.
// TODO: format a nicer message
func (c *Client) NotifySubdomain(subdomain *storage.Subdomain) error {
  msg := fmt.Sprintf("New subdomain found: %s", subdomain.Name)
  for _, port := range subdomain.Ports {
    msg += fmt.Sprintf("\n\tPort: %d/%s %s %s %s", port.Number, port.Protocol, port.Service, port.Product, port.Version)
  }
  if subdomain.Takeover != "" {
    msg += fmt.Sprintf("Vulnerable to subdomain takeover: %s", subdomain.Takeover)
  }
  if err := c.sendMsg(msg); err != nil {
    return err
  }
  for _, port := range subdomain.Ports {
    if port.Screenshot == "" {
      continue
    }
    if _, err := c.slack.UploadFile(slack.FileUploadParameters{
      File: port.Screenshot,
    }); err != nil {
      return fmt.Errorf("failed to upload screnshot of port %v: %v", port, err)
    }
  }
  return nil
}

// sendMsg sends a string to all available slack channels.
func(c *Client) sendMsg(msg string) error {
  for _, channel := range c.channels {
    if _, _, _, err := c.slack.SendMessage(channel, slack.MsgOptionText(msg, false)); err != nil {
      return fmt.Errorf("failed to send slack message: %v", err)
    }
  }
  return nil
}
