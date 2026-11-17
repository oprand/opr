package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

const listUnmappedGeoIPCountryCodesSQL = `
SELECT DISTINCT UPPER(TRIM(g.country_code))
FROM geoip g
WHERE g.country_code IS NOT NULL
	AND TRIM(g.country_code) <> ''
	AND UPPER(TRIM(g.country_code)) NOT IN (
		SELECT UPPER(iso) FROM country_info WHERE iso IS NOT NULL AND TRIM(iso) <> ''
	)
	AND UPPER(TRIM(g.country_code)) NOT IN (
		SELECT UPPER(from_code) FROM country_code_remap
	)
ORDER BY 1
`

// SyncCountryCodeRemap upserts the Go seed (target must exist in country_info;
// source must not be a live ISO unless it is in IntentionalISOOverrides) and
// logs leftover geoip codes that have no ISO target.
func (st *Store) SyncCountryCodeRemap(ctx context.Context) error {
	if err := st.ensureCountryCodeRemapSeed(ctx); err != nil {
		return err
	}
	unmapped, err := st.ListUnmappedGeoIPCountryCodes(ctx)
	if err != nil {
		return err
	}
	if len(unmapped) > 0 {
		st.logger.Info("geoip country codes with no country_info.iso and no remap",
			zap.Strings("country_codes", unmapped))
	}
	return nil
}

// ListUnmappedGeoIPCountryCodes is geoip.country_code EXCEPT country_info.iso
// EXCEPT country_code_remap.from_code.
func (st *Store) ListUnmappedGeoIPCountryCodes(ctx context.Context) ([]string, error) {
	rows, err := st.DB.Query(ctx, listUnmappedGeoIPCountryCodesSQL)
	if err != nil {
		return nil, fmt.Errorf("list unmapped geoip country codes: %w", err)
	}
	defer rows.Close()
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("collect unmapped geoip country codes: %w", err)
	}
	return out, nil
}

func intentionalISOOverrideList() []string {
	out := make([]string, 0, len(IntentionalISOOverrides))
	for cc := range IntentionalISOOverrides {
		out = append(out, cc)
	}
	return out
}

func (st *Store) ensureCountryCodeRemapSeed(ctx context.Context) error {
	if len(CountryCodeRemap) == 0 {
		return nil
	}
	froms := make([]string, 0, len(CountryCodeRemap))
	tos := make([]string, 0, len(CountryCodeRemap))
	for from, to := range CountryCodeRemap {
		froms = append(froms, from)
		tos = append(tos, to)
	}
	_, err := st.DB.Exec(ctx, `
INSERT INTO country_code_remap (from_code, to_code)
SELECT s.from_code, s.to_code
FROM UNNEST($1::text[], $2::text[]) AS s(from_code, to_code)
WHERE EXISTS (
	SELECT 1 FROM country_info ci WHERE UPPER(ci.iso) = s.to_code
)
AND (
	s.from_code = ANY($3::text[])
	OR NOT EXISTS (
		SELECT 1 FROM country_info ci WHERE UPPER(ci.iso) = s.from_code
	)
)
ON CONFLICT (from_code) DO NOTHING
`, froms, tos, intentionalISOOverrideList())
	if err != nil {
		return fmt.Errorf("ensure country_code_remap seed: %w", err)
	}
	return nil
}
