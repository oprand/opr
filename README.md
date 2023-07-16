# `opr` - Oprand CLI Tool

[![vuln](https://github.com/oprand/opr/actions/workflows/vuln.yml/badge.svg?branch=master)](https://github.com/oprand/opr/actions/workflows/vuln.yml)
[![build](https://github.com/oprand/opr/actions/workflows/build.yml/badge.svg?branch=master)](https://github.com/oprand/opr/actions/workflows/build.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/oprand/opr)](https://goreportcard.com/report/github.com/oprand/opr)

The `opr` CLI tool from [oprand.com](https://oprand.com/) offers access to public and private threat data.

* **Public Data:**
  * [ASN](#asn)
* **Private Data:**
  * [Phishing threat and domain impersonation scan results](#private-threat-data)

## Installation

```
go install github.com/oprand/opr/cmd/opr@latest
```

The `opr` binary will be installed in the directory named by the `$GOBIN` environment
variable, which defaults to `$GOPATH/bin` or `$HOME/go/bin` if the `GOPATH`
environment variable is not set.

If you don't have `go` installed, download from our [release page](https://github.com/oprand/opr/releases).

## Public Data

[Oprand](https://oprand.com/) provides a free and public access to some of its in-house aggregated data.

### ASN

* ASN lookup: `opr asn AS3`
* ASN lookup by IP: `opr asn 1.1.1.1`
* ASN lookup by domain: `opr asn example.com`
* ASN lookup by email domain: `opr asn @orange.com`
* Your IP's ASN: `opr asn me`

```bash
# Batch queries possible:
opr asn AS5,8.8.8.8,@google.com

# Return results in JSON:
opr asn --json example.com

## Return all IPs under an ASN:
opr asn --ip AS5

## Return all CIDR under an ASN:
opr asn --cidr AS5

## Read from stdin:
echo tesla.com | opr asn
```

Golang library usage also possible:
```golang
import "github.com/oprand/opr/client"

opr := client.New(client.OprClientParams{})

asnResponse, err := opr.GetAsn("AS3", "1.1.1.1")
if err != nil {
    return err
}

for _, asn := range asnResponse {
    fmt.Printf("input:%s\n", asn.Input)
    fmt.Printf("error:%s\n", asn.Error)
    fmt.Printf("data:%v\n", asn.Output)
}
```

For more information and usage see our [ASN data documentation](https://oprand.com/asn/).


## Private Threat Data

[Oprand](https://oprand.com/) provides phishing threat and domain impersonation detection services.
We publish a public [Phishing Threat Report](https://oprand.com/report).

Access to the data below requires an Oprand account.

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



## Documentation

- See [oprand.com/docs/cli](https://oprand.com/docs/cli)

## Security

- We sign all our commits
- We sign all our releases
- We provide a `SHA-256` checksum for our releases
- The tool doesn't include any auto-updating mechanism
- Dependencies are kept to a minimum and are vetted for any security issue
- The tool only connects to one external domain (oprand.com)
- No analytics or bug report system is included - please [report manually](https://github.com/oprand/opr/issues)

### How To Use Our GPG Public Key

Key signatures allow you verify the files were indeed provided by us. 

1. Download our release signing public key [here](https://oprand.com/.well-known/release-key.pub)
2. Import it with `gpg --import oprand.pub.gpg`
3. Verify it was imported successfully with `gpg --list-keys`

#### Verify Our Releases Signature

After having imported our key, download `opr.checksum.sha256.txt` and its signature `opr-checksums.sha256.txt.sig`, then run:

```bash
gpg --verify --default-key=B2165DEA opr-checksums.sha256.txt.sig opr-checksums.sha256.txt
```

A `gpg: Good signature` message should be displayed.

### How To Verify Our Releases Checksum

Checksums allow you to verify the integrity of the file you downloaded. Ensuring the file hasn't been modified in transit between Github and your system.

Download the `opr.checksum.sha256.txt` file associated with the release. Then from the same folder as your binary's `.zip` file, run:

```bash
# The `--ignore-missing` flag ensures it won't check missing files. 
sha256sum --check --ignore-missing opr.checksum.sha256.txt
```

You should see `OK` on the same line as your binary's `.zip` file.


## License

Copyright (c) Oprand. All rights reserved.
Licensed under the GNU General Public License v3.0
