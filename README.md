<!-- PROJECT LOGO -->
<br />
<p align="center">

  <h3 align="center">Bounty Monitor</h3>

  <p align="center">
    An end-to-end bug bounty monitoring suite
    <br />
    <a href="https://github.com/dlegs/bounty-hunter/issues">Report Bug</a>
    ·
    <a href="https://github.com/dlegs/bounty-hunter/issues">Request Feature</a>
  </p>
</p>



<!-- TABLE OF CONTENTS -->
## Table of Contents

* [About the Project](#about-the-project)
* [Getting Started](#getting-started)
  * [Prerequisites](#prerequisites)
  * [Installation](#installation)
* [Usage](#usage)
* [Roadmap](#roadmap)
* [Contributing](#contributing)
* [License](#license)
* [Contact](#contact)



<!-- ABOUT THE PROJECT -->
## About The Project

[![Product Name Screen Shot][product-screenshot]](https://example.com)

Bounty Hunter glues together various different recon tools and uses Slack to send alerts of any found hosts. The basic workflow is as follows:
1. A list of wildcard domains that belong to companies with bug bounty programs is pulled hourly from [arkadiyt/bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data) and compiled into golang regexes.
2. [Certstream](https://github.com/CaliDog/certstream-go) is used to stream certificate transparency logs, where we look for subdomains that match the pulled regexes.
3. Found subdomains are put under a suite of scans:
  - Port scanned with [nmap](https://nmap.org/)
  - [Subjack](https://github.com/haccer/subjack) is used to check for a possible subdomain takeover
  - If a web server is running on a port, a screenshot is taken via [gowitness](https://github.com/sensepost/gowitness) libraries.
4. An sqlite database is used to keep track of found hosts.
5. Slack is used to fire off notifications.

<!-- GETTING STARTED -->
## Getting Started

To get a local copy up and running follow these steps.

### Prerequisites

This is an example of how to list things you need to use the software and how to install them.
* A Slack App
  * Create one at [https://api.slack.com](https://api.slack.com)
  * Add scopes **channels:read**, **chat:write**, and **files:write**
  * Copy your OAuth Token.
* Nmap
  * `sudo apt-get install -y nmap` or similar.
* Chromium or Chrome
  * `sudo apt-get install -y chromium` or similar.

### Installation
1. Set your slack bot's access token as an environment variable
  `export SLACK_TOKEN=FAKE-SLACK-TOKEN-HERE`

2. `go get`

3. `go build`

<!-- USAGE EXAMPLES -->
## Usage

`./bounty-hunter`

_For more examples, please refer to the [Documentation](https://example.com)_



<!-- ROADMAP -->
## Roadmap

See the [open issues](https://github.com/dlegs/bounty-hunter/issues) for a list of proposed features (and known issues).



<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request



<!-- LICENSE -->
## License

Distributed under the GPLv3 License. See `LICENSE` for more information.



<!-- CONTACT -->
## Contact

Dylan Leggio - [@dylspickle](https://twitter.com/dylspickle) - dylan@legg.io
