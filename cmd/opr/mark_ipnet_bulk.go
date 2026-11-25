package main

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/oprand/opr/aggregator/whoisdb"
	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/internal/oplog"
	"github.com/oprand/opr/store/postgres"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

// runMarkIpnetBulk backfills crawl_target ipnet rows as done from existing
// whoisdb inetnum/inet6num tables (or from --cidr/--registry for a smoke
// test) without downloading dumps again.
func runMarkIpnetBulk(c *cli.Context) error {
	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return err
	}
	logger = logger.Named("opr.registry-crawl")

	dsn := c.String("postgres-db")
	if err := postgres.RunMigrations(logger.Named("store"), dsn); err != nil {
		return err
	}
	st, err := postgres.New(logger.Named("store"), dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	ctx := context.Background()
	dryRun := c.Bool("dry-run")
	cidrs := c.StringSlice("cidr")
	registry := c.String("registry")

	if len(cidrs) > 0 {
		if err := markIpnetBulkFromCIDRs(ctx, logger, st, cidrs, registry, dryRun); err != nil {
			return err
		}
	} else {
		if registry != "" {
			return fmt.Errorf("--registry requires --cidr")
		}
		only := c.StringSlice("only-registries")
		sources, err := resolveBulkCoverageRegistries(only)
		if err != nil {
			return err
		}
		if err := markIpnetBulkFromWhoisDB(ctx, logger, st, sources, dryRun); err != nil {
			return err
		}
	}

	status, err := st.CrawlStatus(ctx, postgres.CrawlKindIpnet)
	if err != nil {
		return err
	}
	if len(status) == 0 {
		logger.Warn("crawl_target has no ipnet rows")
	}
	for _, row := range status {
		logger.Info("crawl_target status",
			zap.String("kind", postgres.CrawlKindIpnet),
			zap.String("registry", row.Registry),
			zap.String("state", row.State),
			zap.Int64("count", row.Count),
		)
	}
	return nil
}

func markIpnetBulkFromWhoisDB(ctx context.Context, logger *zap.Logger, st *postgres.Store, sources []string, dryRun bool) error {
	counts, err := st.CountWhoisInetnumCIDRsBySource(ctx, sources)
	if err != nil {
		return err
	}
	if len(counts) == 0 {
		logger.Warn("no whoisdb inetnum/inet6num rows for coverage registries; run `registry-crawl bulk` first",
			zap.Strings("registries", sources),
		)
		return nil
	}
	for _, row := range counts {
		logger.Info("whoisdb inetnum/inet6num rows",
			zap.String("registry", row.Source),
			zap.Int64("count", row.Count),
		)
	}
	if dryRun {
		logger.Info("dry-run: not writing crawl_target")
		return nil
	}
	n, err := st.MarkIpnetCoveredFromWhoisDB(ctx, sources)
	if err != nil {
		return err
	}
	logger.Info("marked ipnet crawl targets covered by bulk dump",
		zap.Int("count", n),
		zap.Strings("registries", sources),
	)
	return nil
}

func markIpnetBulkFromCIDRs(ctx context.Context, logger *zap.Logger, st *postgres.Store, cidrs []string, registry string, dryRun bool) error {
	if registry == "" {
		return fmt.Errorf("--cidr requires --registry")
	}
	if !whoisdb.IsBulkDumpCoverage(registry) {
		return fmt.Errorf("registry %s is not a complete-dump coverage registry (ARIN/LACNIC dumps are incomplete and are not marked). Valid names: %s",
			registry, strings.Join(whoisdb.BulkDumpCoverageRegistries(), ", "))
	}
	keys, err := canonicalCIDRArgs(cidrs)
	if err != nil {
		return err
	}
	logger.Info("ipnet CIDRs to mark",
		zap.String("registry", registry),
		zap.Strings("cidrs", keys),
	)
	if dryRun {
		logger.Info("dry-run: not writing crawl_target")
		return nil
	}
	if err := st.MarkIpnetCoveredByBulk(ctx, keys, registry); err != nil {
		return err
	}
	logger.Info("marked ipnet crawl targets covered by bulk dump",
		zap.String("registry", registry),
		zap.Int("count", len(keys)),
	)
	return nil
}

func resolveBulkCoverageRegistries(only []string) ([]string, error) {
	allowed := whoisdb.BulkDumpCoverageRegistries()
	if len(only) == 0 {
		return allowed, nil
	}
	for _, r := range only {
		if r == opconst.ARIN || r == opconst.LACNIC {
			return nil, fmt.Errorf("registry %s is not marked for ipnet bulk coverage (dump is incomplete). Valid names: %s",
				r, strings.Join(allowed, ", "))
		}
		if !whoisdb.IsBulkDumpCoverage(r) {
			return nil, fmt.Errorf("unknown registry name: %s. Valid names: %s", r, strings.Join(allowed, ", "))
		}
	}
	return only, nil
}

func canonicalCIDRArgs(cidrs []string) ([]string, error) {
	out := make([]string, 0, len(cidrs))
	for _, raw := range cidrs {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", raw, err)
		}
		out = append(out, n.String())
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--cidr requires at least one CIDR")
	}
	return out, nil
}
