# owl 🦉

Passively monitors **o**nline **W**indows **l**aptops on the local network
by listening for [Computer Browser service](https://en.wikipedia.org/wiki/Browser_service) packets.

## Prerequisites

Install [Tshark](https://tshark.dev/setup/install/).

## Install

TODO

2. Install the package 

## Permissions

The program needs to be run as the `root` user, or your user account must be configured to be able to
[use Wireshark/TShark without root access](https://osqa-ask.wireshark.org/questions/7976/wireshark-setup-linux-for-nonroot-user/).

To setup Wireshark to be used by a non-root user:

1. run `sudo usermod -a -G wireshark $USER`;
2. log out and log back in, or run `newgrp wireshark` in your current shell.

Note that on some OS/distributions the recommended procedure may be different.

> [!WARNING]  
> If run as the `root` user, cache files will be put by default in `/root/.cache/`.

## Features

- passivly listens on the network to capture broadcasted packets
- live captures [Computer Browser protocol](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements#computer-browser)
  datagrams with [Tshark](https://tshark.dev/)
- extracts computer names from request announcements
- stores the results in a SQLite database
- visualize data in a Markdown-compatible table format

## Usage

```
TODO
```

## Future improvements

- add the option to actively send requests to other computers in the network
- add a routine to remove old data from the cache database

## Disclaimer

Users are solely responsible for how they install, configure, and use this software. The developers 
and distributors are not liable for any damages, losses, legal claims, or other consequences arising 
from misuse, unauthorized access, or violation of applicable laws, regulations, or third‑party 
policies. Users must ensure their use complies with all local laws and organizational rules and obtain 
any required permissions before using the software on networks or systems they do not own.

Use of this software may interfere with or violate the privacy of other users on the network by 
exposing or capturing their communications and personal data. Users must not use the software to 
intercept, record, or disclose network traffic or information belonging to others without 
explicit legal authorization and consent, and should take steps to minimize collection and retention 
of sensitive data.
