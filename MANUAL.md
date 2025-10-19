% nftables-dns(1) | nft-dns configuration documentation

# NAME
**nftables-dns** — nftables-dns is a project based on azlux/nft DNS modified according to the MIT license, link: https://github.com/azlux/nft-dns
 
# SYNOPSIS
|    `$ /opt/nft-dns/nft-dns.py --help`

# DESCRIPTION
Back on iptables, fqdn was available into rules, but was resolved at start only. This have never been improved.
This project try to resolve this limitation.

NFT-DNS start with it own configuration file, will resolve the DNS and keep the TTL, then will populate the NFT named SET.

The script will make DNS query each time the TTL reach zero, this way, your system will resolve the entries accept (or refused) by your firewall, even if the domain have change it IP.
The script is both IPv4 and IPv6 compatible.

# FILES
The main configuration file is located at /etc/nft-dns.conf, **DO NOT modify** this file or you will have warning each time the package maintainer modify it.
You can modify it for debug/dev purpose only if you know what you're doing.

You can add you own configuration into the folder /etc/nft-dns.d/*.conf

Only .conf file will be read.

you can use `/etc/nft-dns.conf` as an example for your configuration. All parameter of all section are present (but mostly commented)

## GLOBAL section
This section modify the program. This section is **optional** and can be removed into custom config from `/etc/nft-dns.d/*` if you don't need customization.

- **`[GLOBAL]`**

  That is the name of the program section, **do not change it**.

- `max_ttl` (int)
  
  Default: `86400`
  Limit the max TTL for each entry, allow to update the entries before the real DNS TTL.

- `min_ttl` (int)

  Default: `300`
  Limit of the min TTL, don't allow a refresh be lower than this value.
  This can be impacting is you have fast DNS change (*e.g. deb.debian.org have a 30s TTL*), so you may want to lower this value.

- `mode` (str)

  not implemented yet

- `custom_resolver` (ip)

  Default: not set
  If not set, the system dns server will be used (most of the time, the one into `/etc/resolv.conf`).
  If set, the resolver specified here will be used.

- `dry_run` (bool)

  Default: `False`
  No change will be done one the NFTables. Command will only be print. Useful with Verbose tag.

- `verbose` (bool)

  Default: `False`
  Active the verbose/debug mode.

- `include_config_dir` (str)

  Default (explicit into the package): `/etc/nft-dns.d/`
  If removed, not include will be done.
  This is the path for custom configuration. It's a **Directory**. All `.conf` files inside this folder will be read as part of the configuration.

- `set_type` (str)

    Default: not set
    Please write the type of address in the set you want to create, which can be selected from `ipv4_addr` or `ipv6_addr`

## Other sections
All others sections are your fqdn resolutions configuration.
You need at least one section to make this program work. These sections cannot be named "GLOBAL" since it's used by the program itself.

**All followings parameters are mandatory**

- `[put-a-name-here]` (str)
 
  give a name to your section
 
  non-impacting

  need to be unique

- `set_name` (str)

  This is the Set Name you want to work with. 
  Unlike the original project azlux/nft-DNS, if the set name you write does not exist, a set will be automatically created based on the tables, family, setname, and setotype in the *.conf file, instead of reporting an error and exiting the program

- `enable` (bool)

  no Default
  
  You need to specify if you want to activate this rule with `True` or keep it disabled with `False`

- `family` (str)
  
  no Default

  Choose between `ip`, `ip6` and `inet`. This specifie the nftables "address family" used by the filter.

- `table` (str)

  Default: `filter`

  Tables can be specified to be in output, forward, or custom tables. The default is `filter` because it's the default table name on the debian package. 

- `domains` (str)

  no Default
  
  This is the domain (fqdn) you want to resolve and added to your set.
  
  Multiple fqdn can be specified, separated with `,`

# BUGS
Report issues at: <https://github.com/opennw-rui/nftables-dns/issues>

# AUTHOR
opennw-rui <github@opennw-rui>

# SEE ALSO
Website: <https://github.com/opennw-rui/nftables-dns>

# COPYRIGHT
MIT License

Copyright (c) 2025 opennw-rui

See https://github.com/opennw-rui/nftables-dns/blob/main/LICENSE for the full license
