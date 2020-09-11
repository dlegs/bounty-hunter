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

func Screenshot(subdomain *storage.Subdomain, done chan bool) {
  // Start chrome. Maybe only call this once per run?
  ctx, cancel := chromedp.NewContext(context.Background())
  defer cancel()
  if err := chromedp.Run(ctx, screenshotTasks(subdomain)); err != nil {
    log.Fatalf("failed to execute screenshot tasks: %v", err)
  }
  fmt.Printf("subdomain: %v", subdomain)
  done <- true
}

func screenshotTasks(subdomain *storage.ubdomain) chromedp.Tasks {
  tasks := chromedp.Tasks{}
  for _, port := range subdomain.Ports {
    // Skip ports not running a web server.
    if port.Service != "https" && port.Service != "http" {
      continue
    }
    // Navigate to the url:port.
    tasks = append(tasks, chromedp.Navigate(fmt.Sprintf("%s:%d", port.Subdomain, port.Number)))
    tasks = append(tasks, chromedp.ActionFunc(func(ctx context.Context) error {
      // Capture the screenshot. Maybe adjust quality?
      img, err := page.CaptureScreenshot().WithQuality(90).Do(ctx)
      if err != nil {
        log.Fatalf("failed to capture screenshot: %v", err)
      }
      // Write img to /tmp.
      fileName := fmt.Sprintf("/tmp/%s-%d.png", port.Subdomain, port.Number)
      if err = ioutil.WriteFile(fileName, img, 0644); err != nil {
        log.Fatalf("failed to write img to file: %v", err)
      }
      // Mark where we saved the file.
      port.Screenshot = fileName
      fmt.Printf("port: %v\n", port)
      return nil
    }))
  }
  return tasks
}
