![SS logo](https://raw.githubusercontent.com/malice-plugins/shadow-server/master/docs/logo.png)

# malice-shadow-server

[![Circle CI](https://circleci.com/gh/malice-plugins/shadow-server.png?style=shield)](https://circleci.com/gh/malice-plugins/shadow-server) [![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org) [![Docker Stars](https://img.shields.io/docker/stars/malice/shadow-server.svg)](https://hub.docker.com/r/malice/shadow-server/) [![Docker Pulls](https://img.shields.io/docker/pulls/malice/shadow-server.svg)](https://hub.docker.com/r/malice/shadow-server/) [![Docker Image](https://img.shields.io/badge/docker%20image-34.5MB-blue.svg)](https://hub.docker.com/r/malice/shadow-server/)

Malice ShadowServer Hash Lookup Plugin

This repository contains a **Dockerfile** of the [ShadowServer](https://www.shadowserver.org/wiki/) malice plugin **malice/shadow-server**.

### Dependencies

- [malice/alpine](https://hub.docker.com/r/malice/alpine/)

### Installation

1.  Install [Docker](https://www.docker.io/).
2.  Download [trusted build](https://hub.docker.com/r/malice/shadow-server/) from public [DockerHub](https://hub.docker.com): `docker pull malice/shadow-server`

### Usage

```
docker run --rm malice/shadow-server MD5/SHA1
```

```bash
Usage: shadow-server [OPTIONS] COMMAND [arg...]

Malice ShadowServer Hash Lookup Plugin

Version: v0.1.0, BuildTime: 20160219

Author:
  blacktop - <https://github.com/blacktop>

Options:
  --verbose, -V      verbose output
  --elasitcsearch value  elasitcsearch address for Malice to store results [$MALICE_ELASTICSEARCH]
  --post, -p         POST results to Malice webhook [$MALICE_ENDPOINT]
  --proxy, -x        proxy settings for Malice webhook endpoint [$MALICE_PROXY]
  --table, -t        output as Markdown table
  --help, -h         show help
  --version, -v      print the version

Commands:
  help	Shows a list of commands or help for one command

Run 'shadow-server COMMAND --help' for more information on a command.
```

This will output to stdout and POST to malice results API webhook endpoint.

## Sample Output

### **sandbox** [JSON](https://github.com/malice-plugins/shadow-server/blob/master/docs/sandbox.json):

```json
{
  "shadow-server": {
    "found": true,
    "sandbox": {
      "md5": "aca4aad254280d25e74c82d440b76f79",
      "sha1": "6fe80e56ad4de610304bab1675ce84d16ab6988e",
      "first_seen": "2010-06-15 03:09:41",
      "last_seen": "2010-06-15 03:09:41",
      "type": "exe",
      "ssdeep":
        "12288:gOqOB0v2eZJys73dOvXDpNjNe8NuMpX4aBaa48L/93zKnP6ppgg2HFZlxVPbZX:sOA2eZJ8NI8Nah8L/4PqmTVPlX",
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
    },
    "whitelist": null
  }
}
```

### **whitelist** [JSON](https://github.com/malice-plugins/shadow-server/blob/master/docs/whitelist.json)::

```json
{
  "shadow-server": {
    "found": true,
    "sandbox": {
      "md5": "5e28284f9b5f9097640d58a73d38ad4c",
      "sha1": "7a90f8b051bc82cc9cadbcc9ba345ced02891a6c",
      "first_seen": "2009-07-24 02:09:53",
      "last_seen": "2009-07-24 02:09:53",
      "type": "exe",
      "ssdeep":
        "1536:bwOnbNQKLjWDyy1o5I0foMJUEbooPRrKKReFX3:RNQKPWDyDI0fFJltZrpReFX3",
      "antivirus": {}
    },
    "whitelist": {
      "application_type": "exe",
      "binary": "1",
      "bit": "32",
      "crc32": "877EA041",
      "description": "Notepad",
      "dirname": "c:\\WINDOWS\\system32",
      "filename": "notepad.exe",
      "filesize": "69120",
      "filetimestamp": "04/14/2008 12:00:00",
      "fileversion": "5.1.2600.5512",
      "language": "English",
      "language_code": "1033",
      "md5": "5E28284F9B5F9097640D58A73D38AD4C",
      "media_source": "http://www.microsoft.com/",
      "mfg_name": "Microsoft Corporation",
      "os_mfg": "Microsoft Corporation",
      "os_name":
        "Microsoft Windows XP Professional Service Pack 3 (build 2600)",
      "os_version": "5.1",
      "product_name": "Microsoft Windows Operating System",
      "product_version": "5.1.2600.5512",
      "reference": "os_patches_all",
      "sha1": "7A90F8B051BC82CC9CADBCC9BA345CED02891A6C",
      "sha256":
        "865F34FE7BA81E9622DDBDFC511547D190367BBF3DAD21CEB6DA3EEC621044F5",
      "sha512":
        "CB7218CFEA8813AE8C7ACF6F7511AECBEB9D697986E0EB8538065BF9E3E9C6CED9C29270EB677F5ACF08D2E94B21018D8C4A376AA646FA73CE831FC87D448934",
      "sig_timestamp": "04/14/2008 02:07:47",
      "sig_trustfile":
        "C:\\WINDOWS\\system32\\CatRoot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\NT5.CAT",
      "signer": "Microsoft Windows Component Publisher",
      "source": "AppInfo",
      "source_version": "1.8",
      "strongname_signed": "0",
      "trusted_signature": "1"
    }
  }
}
```

## [Markdown](https://github.com/malice-plugins/shadow-server/blob/master/docs/SAMPLE.md)

### **whitelist** (Markdown Table):

---

#### shadow-server

##### WhiteList

| Found | Filename    | Description | ProductName                        |
| ----- | ----------- | ----------- | ---------------------------------- |
| true  | notepad.exe | Notepad     | Microsoft Windows Operating System |

---

### **sandbox** (Markdown Table):

---

#### shadow-server

##### AntiVirus

- FirstSeen: 6/15/2010 3:09AM
- LastSeen: 6/15/2010 3:09AM

| Vendor           | Signature                  |
| ---------------- | -------------------------- |
| F-Prot6          | W32/Worm.BAOX              |
| G-Data           | Trojan.Generic.2609117     |
| NOD32            | Win32/AutoRun.VB.JP        |
| Avast-Commercial | Win32:Zbot-LRA             |
| DrWeb            | Win32.HLLW.Autoruner.6014  |
| Norman           | Suspicious_Gen2.SKLJ       |
| Panda            | W32/OverDoom.A             |
| Vexira           | Trojan.DL.VB.EEDT          |
| VirusBuster      | Worm.VB.FMYJ               |
| AntiVir          | WORM/VB.NVA                |
| Clam             | Trojan.Downloader-50691    |
| Ikarus           | Trojan-Downloader.Win32.VB |
| Kaspersky        | Trojan.Win32.Cosmu.nyl     |
| QuickHeal        | Worm.VB.at                 |
| VBA32            | Trojan.VBO.011858          |
| AVG7             | Downloader.Generic9.URM    |
| McAfee           | Generic                    |
| Sophos           | Troj/DwnLdr-HQY            |
| TrendMicro       | TROJ_DLOADR.SMM            |
| F-Secure         | Worm:W32/Revois.gen!A      |

---

## Documentation

### To write results to [ElasticSearch](https://www.elastic.co/products/elasticsearch)

```bash
$ docker volume create --name malice
$ docker run -d --name elastic \
                -p 9200:9200 \
                -v malice:/usr/share/elasticsearch/data \
                 blacktop/elasticsearch
$ docker run --rm --link elastic malice/shadow-server -t MD5/SHA1
```

### Issues

Find a bug? Want more features? Find something missing in the documentation? Let me know! Please don't hesitate to [file an issue](https://github.com/malice-plugins/shadow-server/issues/new) and I'll get right on it.

### CHANGELOG

See [`CHANGELOG.md`](https://github.com/malice-plugins/shadow-server/blob/master/CHANGELOG.md)

### Contributing

[See all contributors on GitHub](https://github.com/malice-plugins/shadow-server/graphs/contributors).

Please update the [CHANGELOG.md](https://github.com/malice-plugins/shadow-server/blob/master/CHANGELOG.md) and submit a [Pull Request on GitHub](https://help.github.com/articles/using-pull-requests/).

### License

MIT Copyright (c) 2016 **blacktop**
