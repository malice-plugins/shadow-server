![SS logo](https://raw.githubusercontent.com/maliceio/malice-shadow-server/master/logo.png)
# malice-shadow-server

[![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org)
[![Docker Stars](https://img.shields.io/docker/stars/malice/shadow-server.svg)][hub]
[![Docker Pulls](https://img.shields.io/docker/pulls/malice/shadow-server.svg)][hub]
[![Image Size](https://img.shields.io/imagelayers/image-size/malice/shadow-server/latest.svg)](https://imagelayers.io/?images=malice/shadow-server:latest)
[![Image Layers](https://img.shields.io/imagelayers/layers/malice/shadow-server/latest.svg)](https://imagelayers.io/?images=malice/shadow-server:latest)

Malice ShadowServer Hash Lookup Plugin

This repository contains a **Dockerfile** of **Malice shadow-server Plugin** for [Docker](https://www.docker.io/)'s [trusted build](https://index.docker.io/u/malice/shadow-server/) published to the public [DockerHub](https://index.docker.io/).

> *NOTE:* Currently only supports Public API  
> **WARNING:** Work in progress.  Not ready yet.

### Dependencies

* [gliderlabs/alpine:3.3](https://index.docker.io/_/gliderlabs/alpine/)


### Installation

1. Install [Docker](https://www.docker.io/).
2. Download [trusted build](https://hub.docker.com/r/malice/shadow-server/) from public [DockerHub](https://hub.docker.com): `docker pull malice/shadow-server`

### Usage

    docker run --rm malice/shadow-server --api APIKEY lookup HASH

```bash
Usage: shadow-server [OPTIONS] COMMAND [arg...]

Malice shadow-server Plugin

Version: v0.1.0, BuildTime: 20160214

Author:
  blacktop - <https://github.com/blacktop>

Options:
  --table, -t	output as Markdown table
  --post, -p	POST results to Malice webhook [$MALICE_ENDPOINT]
  --proxy, -x	proxy settings for Malice webhook endpoint [$MALICE_PROXY]
  --api 	shadow-server API key [$MALICE_VT_API]
  --help, -h	show help
  --version, -v	print the version

Commands:
  scan		Upload binary to shadow-server for scanning
  lookup	Get file hash scan report
  help		Shows a list of commands or help for one command

Run 'shadow-server COMMAND --help' for more information on a command.
```

This will output to stdout and POST to malice results API webhook endpoint.

### Sample Output JSON:
```json
{
  "shadow-server": {
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
