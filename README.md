![SS logo](https://raw.githubusercontent.com/maliceio/malice-shadow-server/master/logo.png)
# malice-shadow-server

[![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org)
[![Docker Stars](https://img.shields.io/docker/stars/malice/shadow-server.svg)][hub]
[![Docker Pulls](https://img.shields.io/docker/pulls/malice/shadow-server.svg)][hub]
[![Image Size](https://img.shields.io/imagelayers/image-size/malice/shadow-server/latest.svg)](https://imagelayers.io/?images=malice/shadow-server:latest)
[![Image Layers](https://img.shields.io/imagelayers/layers/malice/shadow-server/latest.svg)](https://imagelayers.io/?images=malice/shadow-server:latest)

Malice ShadowServer Hash Lookup Plugin

This repository contains a **Dockerfile** of **malice/shadow-server** for [Docker](https://www.docker.io/)'s [trusted build](https://index.docker.io/u/malice/shadow-server/) published to the public [DockerHub](https://index.docker.io/).

> **WARNING:** Work in progress.  Not ready yet.

### Dependencies

* [gliderlabs/alpine:3.3](https://index.docker.io/_/gliderlabs/alpine/)


### Installation

1. Install [Docker](https://www.docker.io/).
2. Download [trusted build](https://hub.docker.com/r/malice/shadow-server/) from public [DockerHub](https://hub.docker.com): `docker pull malice/shadow-server`

### Usage

    docker run --rm malice/shadow-server lookup HASH

```bash
Usage: shadow-server [OPTIONS] COMMAND [arg...]

Malice ShadowServer Hash Lookup Plugin

Version: v0.1.0, BuildTime: 20160219

Author:
  blacktop - <https://github.com/blacktop>

Options:
  --post, -p	POST results to Malice webhook [$MALICE_ENDPOINT]
  --proxy, -x	proxy settings for Malice webhook endpoint [$MALICE_PROXY]
  --help, -h	show help
  --version, -v	print the version

Commands:
  lookup	Get file hash sandbox report
  whitelist	test hash against a list of known software applications
  help		Shows a list of commands or help for one command

Run 'shadow-server COMMAND --help' for more information on a command.
```

This will output to stdout and POST to malice results API webhook endpoint.

### Sample Output JSON:
```json
{
  "shadow-server": {
    "md5": "aca4aad254280d25e74c82d440b76f79",
    "sha1": "6fe80e56ad4de610304bab1675ce84d16ab6988e",
    "first_seen": "2010-06-15 03:09:41",
    "last_seen": "2010-06-15 03:09:41",
    "type": "exe",
    "ssdeep": "12288:gOqOB0v2eZJys73dOvXDpNjNe8NuMpX4aBaa48L/93zKnP6ppgg2HFZlxVPbZX:sOA2eZJ8NI8Nah8L/4PqmTVPlX",
    "antivirus": {
      "AVG7": "Downloader.Generic9.URM",
      "AntiVir": "WORM/VB.NVA",
      "Avast-Commercial": "Win32:Zbot-LRA",
      "Clam": "Trojan.Downloader-50691",
      "DrWeb": "Win32.HLLW.Autoruner.6014",
      "F-Prot6": "W32/Worm.BAOX",
      "F-Secure": "Worm:W32/Revois.gen!A",
      "G-Data": "Trojan.Generic.2609117",
      "Ikarus": "Trojan-Downloader.Win32.VB",
      "Kaspersky": "Trojan.Win32.Cosmu.nyl",
      "McAfee": "Generic",
      "NOD32": "Win32/AutoRun.VB.JP",
      "Norman": "Suspicious_Gen2.SKLJ",
      "Panda": "W32/OverDoom.A",
      "QuickHeal": "Worm.VB.at",
      "Sophos": "Troj/DwnLdr-HQY",
      "TrendMicro": "TROJ_DLOADR.SMM",
      "VBA32": "Trojan.VBO.011858",
      "Vexira": "Trojan.DL.VB.EEDT",
      "VirusBuster": "Worm.VB.FMYJ"
    }
  }
}
```
### Sample Output STDOUT (Markdown Table):
---
#### shadow-server


---
### To Run on OSX
 - Install [Homebrew](http://brew.sh)

```bash
$ brew install caskroom/cask/brew-cask
$ brew cask install virtualbox
$ brew install docker
$ brew install docker-machine
$ docker-machine create --driver virtualbox malice
$ eval $(docker-machine env malice)
```

### Documentation

### Issues

Find a bug? Want more features? Find something missing in the documentation? Let me know! Please don't hesitate to [file an issue](https://github.com/maliceio/malice-av/issues/new) and I'll get right on it.

### Credits

### License
MIT Copyright (c) 2016 **blacktop**

[hub]: https://hub.docker.com/r/malice/shadow-server/
