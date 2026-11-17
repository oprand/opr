package postgres

import (
	"context"
	_ "embed"
	"fmt"
	"strings"
)

//go:embed seed/country_legal_flag.sql
var countryLegalFlagSeedSQL string

// ApplyCountryLegalFlagSeed loads the curated country_legal_flag rows from
// the embedded seed. The statements are idempotent: DELETE retires the old
// flag names, and each INSERT is ON CONFLICT DO UPDATE of source, as_of,
// and notes. A second call does not add rows. RunMigrations does not call
// this; `opr geonames flags --apply` does.
func (st *Store) ApplyCountryLegalFlagSeed(ctx context.Context) error {
	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return fmt.Errorf("apply country_legal_flag seed: %w", err)
	}
	defer tx.Rollback(ctx)

	stmts := splitSQLStatements(countryLegalFlagSeedSQL)
	if len(stmts) == 0 {
		return fmt.Errorf("apply country_legal_flag seed: embedded SQL has no statements")
	}
	for i, stmt := range stmts {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("apply country_legal_flag seed statement %d: %w", i+1, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("apply country_legal_flag seed: %w", err)
	}
	return nil
}

// splitSQLStatements breaks the seed file into statements. Full-line --
// comments are dropped. In this seed, semicolons are statement terminators
// and do not appear inside quotes.
func splitSQLStatements(sql string) []string {
	var out []string
	var b strings.Builder
	for _, line := range strings.Split(sql, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "--") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
		if strings.HasSuffix(trim, ";") {
			if stmt := strings.TrimSpace(b.String()); stmt != "" {
				out = append(out, stmt)
			}
			b.Reset()
		}
	}
	if rest := strings.TrimSpace(b.String()); rest != "" {
		out = append(out, rest)
	}
	return out
}
