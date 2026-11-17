package rdns

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/store/postgres"

	"go.uber.org/zap"
	"golang.org/x/text/encoding/charmap"
)

const maxDumpCompressedBytes = 512 << 20

func (in *Ingestor) ingestWhoisDumps(ctx context.Context) error {
	if in.SkipWhois {
		return nil
	}
	dumps := in.WhoisDumps
	if dumps == nil {
		return nil
	}
	var errs []error
	for _, dump := range dumps {
		if dump.URL == "" || dump.Name == "" {
			continue
		}
		if dump.Kind == WhoisDumpLacnicInetnum {
			continue
		}
		if err := in.ingestWhoisDump(ctx, dump); err != nil {
			in.Logger.Error("rdns WHOIS dump failed; last good rows kept",
				zap.String("source", dump.Name), zap.String("url", dump.URL), zap.Error(err))
			errs = append(errs, fmt.Errorf("%s whois: %w", dump.Name, err))
		}
	}
	return errors.Join(errs...)
}

func (in *Ingestor) ingestLacnicNserver(ctx context.Context) error {
	if in.SkipLacnic {
		return nil
	}
	url := strings.TrimSpace(in.LacnicDBURL)
	if url == "" {
		return nil
	}
	return in.ingestWhoisDump(ctx, WhoisDump{
		Name: opconst.LACNIC,
		URL:  url,
		Kind: WhoisDumpLacnicInetnum,
	})
}

func (in *Ingestor) ingestWhoisDump(ctx context.Context, dump WhoisDump) error {
	var newMeta *postgres.ResponseMetadataItem
	if !in.Force {
		var changed bool
		newMeta, changed = fileChanged(ctx, in.Store, in.Client, dump.URL)
		if !changed {
			in.Logger.Info("rdns WHOIS dump not changed", zap.String("url", dump.URL))
			return nil
		}
	}

	body, hdr, err := in.openDump(ctx, dump.URL)
	if err != nil {
		return err
	}
	defer body.Close()
	if newMeta == nil {
		newMeta = metadataFromHeader(dump.URL, hdr)
	}

	charset := CharsetUTF8
	if dump.Kind == WhoisDumpLacnicInetnum {
		charset = CharsetISO8859
	}

	var rows []postgres.RDNSDelegation
	switch dump.Kind {
	case WhoisDumpLacnicInetnum:
		rows, err = parseLacnicNserver(body, dump.Name, dump.URL, charset)
	default:
		rows, err = parseReverseDomains(body, dump.Name, dump.URL, charset)
	}
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		in.Store.SaveResponseMetadata(newMeta)
		in.Logger.Warn("rdns empty_zone; WHOIS dump had no reverse objects",
			zap.String("source", dump.Name),
			zap.String("url", dump.URL),
			zap.Bool("empty_zone", true))
		return nil
	}

	if err := in.Store.UpsertRDNSDelegations(ctx, rows); err != nil {
		return err
	}
	in.Store.SaveResponseMetadata(newMeta)
	in.Logger.Info("rdns WHOIS enrich persisted",
		zap.String("source", dump.Name),
		zap.String("url", dump.URL),
		zap.Int("rows", len(rows)))
	return nil
}

func parseReverseDomains(r io.Reader, source, sourceURL, charset string) ([]postgres.RDNSDelegation, error) {
	now := time.Now().UTC()
	method := postgres.FetchMethodWhoisDomain
	partial := true
	var out []postgres.RDNSDelegation
	err := eachRPSL(r, charset, func(attrs []rpslAttr) error {
		if rpslClass(attrs) != "domain" {
			return nil
		}
		zone := canonicalZone(rpslFirst(attrs, "domain"))
		if !isReverseZone(zone) {
			return nil
		}
		prefix, err := ZoneToPrefix(zone)
		if err != nil {
			return nil
		}
		nservers := rpslAll(attrs, "nserver")
		for i := range nservers {
			nservers[i] = canonicalName(nservers[i])
		}
		out = append(out, postgres.RDNSDelegation{
			Zone:               zone,
			Prefix:             prefix,
			Nservers:           compactStrings(nservers),
			Source:             source,
			SourceURL:          sourceURL,
			Org:                rpslFirst(attrs, "org"),
			AdminC:             rpslAll(attrs, "admin-c"),
			TechC:              rpslAll(attrs, "tech-c"),
			MntBy:              rpslAll(attrs, "mnt-by"),
			MetaAddedAt:        &now,
			LastFetchedAt:      &now,
			FetchMethod:        &method,
			IsPartial:          partial,
			LastSeenInSourceAt: &now,
		})
		return nil
	})
	return out, err
}

func parseLacnicNserver(r io.Reader, source, sourceURL, charset string) ([]postgres.RDNSDelegation, error) {
	now := time.Now().UTC()
	method := postgres.FetchMethodWhoisInetnum
	partial := true
	var out []postgres.RDNSDelegation
	err := eachRPSL(r, charset, func(attrs []rpslAttr) error {
		class := rpslClass(attrs)
		if class != "inetnum" && class != "inet6num" {
			return nil
		}
		nservers := rpslAll(attrs, "nserver")
		if len(nservers) == 0 {
			return nil
		}
		inet := rpslFirst(attrs, class)
		prefix := inetnumToPrefix(inet)
		if prefix == "" {
			return nil
		}
		zone, err := PrefixToZone(prefix)
		if err != nil {
			return nil
		}
		for i := range nservers {
			nservers[i] = canonicalName(nservers[i])
		}
		out = append(out, postgres.RDNSDelegation{
			Zone:               zone,
			Prefix:             prefix,
			Nservers:           compactStrings(nservers),
			Source:             source,
			SourceURL:          sourceURL,
			Org:                rpslFirst(attrs, "org"),
			AdminC:             rpslAll(attrs, "admin-c"),
			TechC:              rpslAll(attrs, "tech-c"),
			MntBy:              rpslAll(attrs, "mnt-by"),
			MetaAddedAt:        &now,
			LastFetchedAt:      &now,
			FetchMethod:        &method,
			IsPartial:          partial,
			LastSeenInSourceAt: &now,
		})
		return nil
	})
	return out, err
}

func isReverseZone(zone string) bool {
	z := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), "."))
	return strings.HasSuffix(z, ".in-addr.arpa") || strings.HasSuffix(z, ".ip6.arpa") ||
		z == "in-addr.arpa" || z == "ip6.arpa"
}

func compactStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func inetnumToPrefix(inet string) string {
	inet = strings.TrimSpace(inet)
	if !strings.Contains(inet, "/") {
		return ""
	}
	_, ipnet, err := net.ParseCIDR(normalizeIPv4CIDR(inet))
	if err != nil {
		return ""
	}
	return ipnet.String()
}

func normalizeIPv4CIDR(cidr string) string {
	host, prefix, ok := strings.Cut(cidr, "/")
	if !ok || strings.Contains(host, ":") {
		return cidr
	}
	n := strings.Count(host, ".") + 1
	if n >= 4 {
		return cidr
	}
	return host + strings.Repeat(".0", 4-n) + "/" + prefix
}

func (in *Ingestor) openDump(ctx context.Context, rawURL string) (io.ReadCloser, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := in.Client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, nil, fmt.Errorf("status %s", resp.Status)
	}
	limited := &dumpLimitCloser{
		Reader: io.LimitReader(resp.Body, maxDumpCompressedBytes+1),
		body:   resp.Body,
		max:    maxDumpCompressedBytes,
	}
	name := strings.ToLower(path.Base(rawURL))
	enc := strings.ToLower(resp.Header.Get("Content-Encoding"))
	if strings.HasSuffix(name, ".gz") || strings.Contains(enc, "gzip") {
		zr, err := gzip.NewReader(limited)
		if err != nil {
			limited.Close()
			return nil, nil, fmt.Errorf("gzip: %w", err)
		}
		return &gzipDumpCloser{gzip: zr, inner: limited}, resp.Header, nil
	}
	return limited, resp.Header, nil
}

type dumpLimitCloser struct {
	io.Reader
	body io.ReadCloser
	max  int64
	n    int64
}

func (d *dumpLimitCloser) Read(p []byte) (int, error) {
	n, err := d.Reader.Read(p)
	d.n += int64(n)
	if d.n > d.max {
		return n, fmt.Errorf("rdns: dump exceeds %d bytes", d.max)
	}
	return n, err
}

func (d *dumpLimitCloser) Close() error {
	return d.body.Close()
}

type gzipDumpCloser struct {
	gzip  *gzip.Reader
	inner io.Closer
}

func (g *gzipDumpCloser) Read(p []byte) (int, error) { return g.gzip.Read(p) }

func (g *gzipDumpCloser) Close() error {
	_ = g.gzip.Close()
	return g.inner.Close()
}

const (
	CharsetUTF8    = "utf-8"
	CharsetISO8859 = "iso-8859-1"
)

type rpslAttr struct {
	Key   string
	Value string
}

func eachRPSL(r io.Reader, charset string, fn func([]rpslAttr) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 2<<20)
	var attrs []rpslAttr
	flush := func() error {
		if len(attrs) == 0 {
			return nil
		}
		err := fn(attrs)
		attrs = nil
		return err
	}
	for sc.Scan() {
		line := decodeRPSLLine(sc.Text(), charset)
		trim := strings.TrimSpace(line)
		if trim == "" {
			if err := flush(); err != nil {
				return err
			}
			continue
		}
		if trim[0] == '#' || trim[0] == '%' {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' || line[0] == '+' {
			if len(attrs) == 0 {
				continue
			}
			extra := strings.TrimSpace(line)
			if extra == "" {
				continue
			}
			attrs[len(attrs)-1].Value += " " + extra
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		attrs = append(attrs, rpslAttr{
			Key:   strings.ToLower(strings.TrimSpace(key)),
			Value: strings.TrimSpace(val),
		})
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return flush()
}

func decodeRPSLLine(line, charset string) string {
	if charset != CharsetISO8859 || utf8.ValidString(line) {
		return line
	}
	decoded, err := charmap.ISO8859_1.NewDecoder().String(line)
	if err != nil {
		return line
	}
	return decoded
}

func rpslClass(attrs []rpslAttr) string {
	if len(attrs) == 0 {
		return ""
	}
	return attrs[0].Key
}

func rpslFirst(attrs []rpslAttr, key string) string {
	for _, a := range attrs {
		if a.Key == key {
			return a.Value
		}
	}
	return ""
}

func rpslAll(attrs []rpslAttr, key string) []string {
	var out []string
	for _, a := range attrs {
		if a.Key == key && a.Value != "" {
			out = append(out, a.Value)
		}
	}
	return out
}
