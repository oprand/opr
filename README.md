# `opr` - Oprand CLI Tool

[Oprand](https://oprand.com/) provides phishing threat and domain impersonation detection services. We publish a public [Phishing Threat Report](https://oprand.com/report).

This CLI tool helps you fetch your latest scan data.

```
$ opr results --query=web,ssl example.com

-  exämple.co  fuzzer:homoglyph+tld-swap  scanned:2023-03-05 14:52 (14min ago)
DNS
    A          203.0.113.4
    NS         ns1.domain.com  ns2.domain.com
    TXT        v=spf1 ip4:203.0.113.0/18 ?all
    MX         mx.exämple.nco
    SPF        v=spf1 ip4:203.0.113.0/18 ?all
WHOIS
    DOMAIN   REGISTERED .. 2022-04-15T00:38:46Z (50w5h ago)
             UPDATED ..... 2022-04-15T00:38:46Z (50w5h ago)
             EXPIRING .... 2024-04-15T00:38:46Z (in 1y2w)
    REGISTRAR   Domain.com, LLC
                compliance@domain-inc.net  602-226-2389
                IANA ID: 886
    REGISTRANT  UNKNOWN
WEB
    VALID URL    https://exämple.co
    HTTP BANNER  Apache/2
    HTTP STATUS  200
    HTML TITLE   The real example.com website
    CRED. HARVESTER YES
    MENTION DOMAIN  NO
    MENTION BRAND   YES
    REDIRECT        NO
SSL
    ISSUER  R3, Let's Encrypt
            US
    CERT    EXPIRES .... 2024-05-16 14:56:09 +0000 UTC
            SIGNATURE .. SHA256-RSA / CDE4B59A (last 8 char)
            SUBJECT .... CN=*.exämple.co.net
            ISSUER ..... CN=R3,O=Let's Encrypt,C=US

# ... 100s of more results
```

## Installation

```
go install github.com/oprand/opr/cmd/opr@latest
```

The `opr` binary will be installed in the directory named by the `$GOBIN` environment
variable, which defaults to `$GOPATH/bin` or `$HOME/go/bin` if the `GOPATH`
environment variable is not set.

If you don't have `go` installed, download our [latest release](https://github.com/oprand/opr/releases).

## Documentation

- See [oprand.com/docs/cli](https://oprand.com/docs/cli)

## Security

- We sign all our commits
- We sign all our releases
- We provide a `SHA-256` checksum for our releases
- The tool doesn't include any auto-updating mechanism
- Dependencies are kept to a minimum and are vetted for any security issue
- The tool only connects to one external domain that oprand.com operates

### How To Use Our Public Key

Key signatures allow you verify the binary was indeed provided by us. Here is our release signing public key:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
mDMEZCcUsRYJKwYBBAHaRw8BAQdAYrE35lXe9a5iX1A7PKrMT0f/WG2zsOZaXWsG
3Azl/9+0H09wcmFuZCA8cmVsZWFzZS1rZXlAb3ByYW5kLmNvbT6ImQQTFgoAQRYh
BLIWXeqG6SOaZP4kivMsieKupYdgBQJkJxSxAhsDBQkDwmcABQsJCAcCAiICBhUK
CQgLAgQWAgMBAh4HAheAAAoJEPMsieKupYdgG4wBAJqzDeSq80+eYEHyLM5+NZAT
bgPDj8gEpZW6PoQC7hISAQCEUGClpa8tqtR+PBfGvMm6yCOcaFZMtlaXBw+eKj2k
B7g4BGQnFLESCisGAQQBl1UBBQEBB0A0m/8Pr4fn6XpQXAS8YTAB4ikbpudbYU4i
+xVKM7O1DAMBCAeIfgQYFgoAJhYhBLIWXeqG6SOaZP4kivMsieKupYdgBQJkJxSx
AhsMBQkDwmcAAAoJEPMsieKupYdgJowBAKBbq10/yaI9PNB523SsQS7JtQPa/TsI
AG7g3mb/N7InAP46RTjbswObz5eAWhP8t2W058JHGwBSzVAgavRtXqkkAw==
=16ZD
-----END PGP PUBLIC KEY BLOCK-----
```

#### Import Our Public Key

Once you saved our public key above into a file named `oprand.pub.gpg`, run this command:

```
gpg --import oprand.pub.gpg
```

You can verify it was imported successfully with `gpg --list-keys`.

#### Verify Our Releases Signature

After having imported our key, and downloaded the binary `opr` and its signature file `opr.sig`, run:

```
gpg --verify --default-key=B2165DEA86E9239A64FE248AF32C89E2AEA58760 opr.sig opr
```

A `gpg: Good signature` message should be displayed with other information.

### How To Verify Our Releases Checksum

Checksum allows you to verify the integrity of the binary you downloaded.

Download the `opr.sha256` file associated with the release. Then from the same folder as the `opr` binary, run:

```
sha256sum --check opr.checksum
```

You should see `opr: OK` on the screen.

## License

Copyright (c) Oprand. All rights reserved.
Licensed under the GNU General Public License v3.0
