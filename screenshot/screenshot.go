// package screenshot takes a screenshot of web servers running on a host.
package screenshot

import (
  "context"
  "fmt"
  "io/ioutil"
  "log"

  "github.com/dlegs/bounty-hunter/storage"
  "github.com/chromedp/chromedp"
  "github.com/chromedp/cdproto/page"
)

// Client holds a Chrome context.
type Client struct {
  ctx context.Context
  cancel context.CancelFunc
}

// New creates a chrome context.
func New(ctx context.Context) *Client {
  c := &Client{}
  c.ctx, c.cancel = chromedp.NewContext(ctx)
  return c
}

func (c *Client) Close() {
  c.cancel()
}

func(c *Client) Screenshot(subdomain *storage.Subdomain, done chan bool) {
  for _, port := range subdomain.Ports {
    if port.Service != "http" && port.Service != "https" {
      continue
    }
    var buf []byte
    scheme := "http"
    if port.Service == "https" || port.Number == 443 || port.Number == 8443 {
      scheme = "https"
    }
    url := fmt.Sprintf("%s://%s:%d", scheme, port.Subdomain, port.Number)
    fileName := fmt.Sprintf("/tmp/%s-%d.png", port.Subdomain, port.Number)
    if err := chromedp.Run(c.ctx, tasks(url, &buf)); err != nil {
      log.Fatalf("failed to run chrome tasks: %v", err)
    }
    if err := ioutil.WriteFile(fileName, buf, 0644); err != nil {
      log.Fatalf("failed to write image to disk: %v", err)
    }
    port.Screenshot = fileName
  }

  done <- true
}

func tasks(url string, res *[]byte) chromedp.Tasks {
  // TODO: possibly wait for page to load?
  return chromedp.Tasks{
    chromedp.Navigate(url),
    chromedp.ActionFunc(func(ctx context.Context) (err error) {
      *res, err = page.CaptureScreenshot().WithQuality(90).Do(ctx)
      if err != nil {
        return fmt.Errorf("failed to capture screenshot of page %s: %v", url, err)
      }
      return nil
    }),
  }
}
