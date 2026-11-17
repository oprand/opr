-- Curated country_legal_flag rows. Applied by `opr geonames flags --apply`.
-- Not a migration: 0001_initial creates the table and stays schema-only.
-- Idempotent: the DELETEs retire old flag names, and each INSERT refreshes
-- source, as_of, and notes on conflict. A second apply does not add rows.

-- Every seed statement below has the same shape so the seed can be read
-- back and checked without a database:
--   SELECT t.iso, '<flag>', '<admin1_code>', '<source>', DATE '<as_of>', '<notes>'
--   FROM UNNEST(ARRAY[...]) AS t(iso)
-- Superset clubs repeat their members on purpose (five_eyes members are
-- also seeded as nine_eyes and fourteen_eyes).
--
-- NAMING: a flag name must describe exactly what WHERE flag = '<name>'
-- returns, because that predicate is the whole interface. Where the
-- everyday word is looser than the seeded list, the qualifier is in the
-- name and not only in source:
--   eea_efta            the non-EU remainder of the EEA (IS, LI, NO).
--                       The full EEA is eu UNION eea_efta; a bare 'eea'
--                       returned three rows to a reader expecting thirty.
--   ofac_comprehensive  OFAC comprehensive country programs only (CU, IR,
--                       KP). A bare 'ofac' read as "sanctioned", which is
--                       false for RU/BY/VE/AF/MM under list-based or
--                       sectoral programs that are not seeded here.

-- Re-runnable: this file is an ON CONFLICT DO UPDATE refresh, so applying
-- it twice is a no-op. These two DELETEs retire the earlier spellings of
-- the flags renamed above, so a database that applied a previous draft
-- cannot end up carrying both names for the same fact.
DELETE FROM country_legal_flag WHERE flag = 'eea';
DELETE FROM country_legal_flag WHERE flag = 'ofac';

-- Privacy: EU membership. 27 members; no accession since HR in 2013.
INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'eu', '', 'eu_members', DATE '2026-09-09', 'European Union member state'
FROM UNNEST(ARRAY['AT','BE','BG','HR','CY','CZ','DK','EE','FI','FR','DE','GR','HU','IE','IT','LV','LT','LU','MT','NL','PL','PT','RO','SK','SI','ES','SE']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;

-- Privacy: GDPR territorial scope = EU 27 + the three non-EU EEA states.
-- This is todo.md is_grpd. The EU-integral territories that geoip reports
-- under their own alpha-2 code are a third INSERT below; they belong to
-- this flag but not to 'eu'.
INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'gdpr', '', 'gdpr_scope', DATE '2026-09-09', 'EU GDPR applies (EU member or non-EU EEA state)'
FROM UNNEST(ARRAY['AT','BE','BG','HR','CY','CZ','DK','EE','FI','FR','DE','GR','HU','IE','IT','LV','LT','LU','MT','NL','PL','PT','RO','SK','SI','ES','SE','IS','LI','NO']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;

-- Privacy: the EEA EFTA states, i.e. the non-EU remainder of the EEA.
-- Named eea_efta and not eea because WHERE flag = 'eea' returning three
-- rows surprises a reader who means the whole thirty-state area. The full
-- EEA is flag eu UNION flag eea_efta.
INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'eea_efta', '', 'eea_efta', DATE '2026-09-09', 'EEA EFTA state (non-EU part of the EEA); full EEA = eu UNION eea_efta'
FROM UNNEST(ARRAY['IS','LI','NO']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;

-- Privacy: EU-integral territories that geoip and GeoNames report under
-- their own alpha-2 code. Without a row each they resolve to zero flags,
-- which a caller reads as "GDPR does not apply" — wrong, and wrong in the
-- expensive direction.
--
-- eu vs gdpr. 'eu' is the member-state list: 27 rows, one per state, so
-- WHERE flag = 'eu' can be trusted to answer "is this a member state".
-- None of these territories is a member state in its own right; each is
-- covered because it is part of FI or FR. So they get 'gdpr' (the law
-- applies) and 'schengen' where the acquis really reaches, and never 'eu'.
--
-- AX Aland Islands. Autonomous region of Finland, inside the EU and
--    inside the Schengen area (its EU protocol carves out VAT and excise,
--    not data protection and not free movement). gdpr + schengen.
--
-- Article 349 TFEU outermost regions of France. EU territory, EU law
-- including the GDPR applies in full, but they are OUTSIDE the Schengen
-- area: the Schengen acquis covers the European territory of France only,
-- and each of these keeps its own entry rules and border checks against
-- metropolitan France. gdpr, deliberately no schengen:
--    GF French Guiana, GP Guadeloupe, MQ Martinique, RE Reunion,
--    YT Mayotte (outermost region since 2014),
--    MF Saint-Martin (outermost region; the French northern half only).
--
-- Deliberately NOT seeded, and why:
--  * BL Saint-Barthelemy left outermost-region status for Annex II TFEU
--    OCT status on 2012-01-01. EU law, and so the GDPR, does not apply.
--    BL sits next to MF on the same island; the pair is the reason this
--    list is spelled out rather than derived from "French overseas".
--  * The other Annex II OCTs: PM Saint-Pierre and Miquelon, NC New
--    Caledonia, PF French Polynesia, WF Wallis and Futuna, TF French
--    Southern Territories, AW Aruba, CW Curacao, SX Sint Maarten,
--    BQ Bonaire/Sint Eustatius/Saba, GL Greenland. Associated with the
--    EU, not part of it.
--  * SJ Svalbard: excluded from Norway's EEA accession, so it is outside
--    the EEA and outside GDPR scope even though NO is inside both.
--  * The Canary Islands (ES), Madeira and the Azores (PT) are outermost
--    regions too, but neither GeoNames countryInfo nor the geoip feeds
--    give them an alpha-2 of their own: they are reported as ES and PT
--    and already resolve to the member state's rows. ISO 3166-1 does
--    exceptionally reserve IC and EA, but nothing in this pipeline emits
--    them, so a row would only be dead weight. Same for the German,
--    Italian and Greek islands, all reported under DE/IT/GR.
--  * GI Gibraltar left the EU with the UK and carries uk_gdpr territory
--    rules, not the EU GDPR; it is not seeded here.
INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'gdpr', '', 'gdpr_scope_territory', DATE '2026-09-09', 'EU GDPR applies: EU-integral territory of a member state, reported under its own alpha-2 code; not an EU member state itself'
FROM UNNEST(ARRAY['AX','GF','GP','MQ','RE','YT','MF']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;

-- Privacy: UK GDPR + Data Protection Act 2018 after Brexit.
INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'uk_gdpr', '', 'uk_dpa_2018', DATE '2026-09-09', 'UK GDPR and Data Protection Act 2018'
FROM UNNEST(ARRAY['GB']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;

-- Privacy: revised Swiss Federal Act on Data Protection (in force 2023).
INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'ch_fadp', '', 'ch_nfadp', DATE '2026-09-09', 'revised Swiss Federal Act on Data Protection'
FROM UNNEST(ARRAY['CH']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;

-- Privacy: European Commission adequacy decisions. CA is commercial
-- organisations only (PIPEDA). US is NOT here: the Data Privacy
-- Framework is certification-scoped, not blanket adequacy, so it gets
-- its own flag below.
INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'eu_adequacy', '', 'ec_adequacy', DATE '2026-09-09', 'European Commission adequacy decision; CA covers commercial organisations only'
FROM UNNEST(ARRAY['AD','AR','CA','FO','GG','IL','IM','JP','JE','KR','NZ','CH','GB','UY']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;

-- Privacy: EU-US Data Privacy Framework. Separate flag because it only
-- covers self-certified US organisations, so it must never be read as
-- eu_adequacy for the whole country.
INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'eu_adequacy_us_dpf', '', 'ec_adequacy_dpf', DATE '2026-09-09', 'EU-US Data Privacy Framework; covers self-certified organisations only, not the country'
FROM UNNEST(ARRAY['US']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;

-- Privacy: other comprehensive national statutes, one flag each so no
-- caller has to guess which regime a gdpr-like label meant.
INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'br_lgpd', '', 'br_lgpd', DATE '2026-09-09', 'Lei Geral de Protecao de Dados'
FROM UNNEST(ARRAY['BR']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;

INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'ca_pipeda', '', 'ca_pipeda', DATE '2026-09-09', 'Personal Information Protection and Electronic Documents Act'
FROM UNNEST(ARRAY['CA']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;

INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'jp_appi', '', 'jp_appi', DATE '2026-09-09', 'Act on the Protection of Personal Information'
FROM UNNEST(ARRAY['JP']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;

INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'kr_pipa', '', 'kr_pipa', DATE '2026-09-09', 'Personal Information Protection Act'
FROM UNNEST(ARRAY['KR']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;

INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'za_popia', '', 'za_popia', DATE '2026-09-09', 'Protection of Personal Information Act'
FROM UNNEST(ARRAY['ZA']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;

INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'au_privacy', '', 'au_privacy_act_1988', DATE '2026-09-09', 'Privacy Act 1988 and Australian Privacy Principles'
FROM UNNEST(ARRAY['AU']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;

INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'in_dpdp', '', 'in_dpdp_act_2023', DATE '2026-09-09', 'Digital Personal Data Protection Act 2023'
FROM UNNEST(ARRAY['IN']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;

INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'cn_pipl', '', 'cn_pipl', DATE '2026-09-09', 'Personal Information Protection Law'
FROM UNNEST(ARRAY['CN']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;

-- Privacy, place-specific: CCPA/CPRA is California, not the US. This is
-- the only row in the seed with a non-empty admin1_code; it lines up
-- with geonames_admin1.code = 'US.CA'.
INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'us_ccpa', 'CA', 'ccpa_cpra', DATE '2026-09-09', 'California Consumer Privacy Act as amended by CPRA; California only, geonames_admin1 code US.CA'
FROM UNNEST(ARRAY['US']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;

-- Sanctions: OFAC comprehensive country programs only, and the flag is
-- named ofac_comprehensive so the predicate cannot be misread as "any
-- OFAC program". Country-wide embargo, not the SDN entity list and not
-- sectoral/list-based programs (RU, BY, VE, AF, MM are deliberately
-- absent: extensive but not comprehensive, and a bare 'ofac' would have
-- implied the opposite). SY is absent because the Syria program was
-- revoked in 2025; re-add only after confirming the current state. No
-- ofac_city / region rows: the Ukraine covered-region programs need
-- admin1 codes we have not confirmed against the dump.
INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'ofac_comprehensive', '', 'ofac_comprehensive', DATE '2026-09-09', 'OFAC comprehensive country program (country-wide embargo), not the SDN entity list and not sectoral programs'
FROM UNNEST(ARRAY['CU','IR','KP']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;

-- Intel: UKUSA Agreement. Supersets are separate flags, so a five_eyes
-- member is seeded three times (five/nine/fourteen) and
-- WHERE flag = 'five_eyes' stays exactly the five.
INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'five_eyes', '', 'ukusa', DATE '2026-09-09', 'UKUSA Agreement SIGINT partner'
FROM UNNEST(ARRAY['AU','CA','NZ','GB','US']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;

-- Intel: Nine Eyes = Five Eyes + DK FR NL NO.
INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'nine_eyes', '', 'ukusa', DATE '2026-09-09', 'Nine Eyes: Five Eyes plus DK FR NL NO'
FROM UNNEST(ARRAY['AU','CA','NZ','GB','US','DK','FR','NL','NO']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;

-- Intel: SIGINT Seniors Europe = Nine Eyes + BE DE IT ES SE. No
-- third-party / SSEUR-adjacent list beyond this: those are unofficial.
INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'fourteen_eyes', '', 'sseur', DATE '2026-09-09', 'SIGINT Seniors Europe: Nine Eyes plus BE DE IT ES SE'
FROM UNNEST(ARRAY['AU','CA','NZ','GB','US','DK','FR','NL','NO','BE','DE','IT','ES','SE']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;

-- Gov: AUKUS security partnership.
INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'aukus', '', 'aukus', DATE '2026-09-09', 'AUKUS security partnership'
FROM UNNEST(ARRAY['AU','GB','US']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;

-- Gov: NATO, 32 members (FI 2023, SE 2024). Static seed, never scraped.
INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'nato', '', 'nato_members', DATE '2026-09-09', 'NATO member state'
FROM UNNEST(ARRAY['AL','BE','BG','CA','HR','CZ','DK','EE','FI','FR','DE','GR','HU','IS','IT','LV','LT','LU','ME','NL','MK','NO','PL','PT','RO','SK','SI','ES','SE','TR','GB','US']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;

-- Gov: Schengen Area, 29 states (BG and RO became full members
-- 2025-01-01). EU members IE and CY are deliberately absent.
INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'schengen', '', 'schengen_acquis', DATE '2026-09-09', 'Schengen Area state'
FROM UNNEST(ARRAY['AT','BE','BG','HR','CZ','DK','EE','FI','FR','DE','GR','HU','IS','IT','LV','LI','LT','LU','MT','NL','NO','PL','PT','RO','SK','SI','ES','SE','CH']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;

-- Gov: Schengen, territory rows. Aland is inside the area through
-- Finland and is reported as AX, so it needs its own row. The French
-- outermost regions are the opposite case and are absent on purpose:
-- they carry gdpr above but the Schengen acquis does not reach them.
INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'schengen', '', 'schengen_acquis_territory', DATE '2026-09-09', 'inside the Schengen Area as a territory of a member state, reported under its own alpha-2 code'
FROM UNNEST(ARRAY['AX']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;

-- Gov: OECD, 38 members (CR 2021 was the most recent accession).
INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'oecd', '', 'oecd_members', DATE '2026-09-09', 'OECD member country'
FROM UNNEST(ARRAY['AU','AT','BE','CA','CL','CO','CR','CZ','DK','EE','FI','FR','DE','GR','HU','IS','IE','IL','IT','JP','KR','LV','LT','LU','MX','NL','NZ','NO','PL','PT','SK','SI','ES','SE','CH','TR','GB','US']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;

-- Gov: Council of Europe, 46 members (RU expelled 2022).
INSERT INTO country_legal_flag (iso, flag, admin1_code, source, as_of, notes)
SELECT t.iso, 'council_of_europe', '', 'coe_members', DATE '2026-09-09', 'Council of Europe member state'
FROM UNNEST(ARRAY['AL','AD','AM','AT','AZ','BE','BA','BG','HR','CY','CZ','DK','EE','FI','FR','GE','DE','GR','HU','IS','IE','IT','LV','LI','LT','LU','MT','MD','MC','ME','NL','MK','NO','PL','PT','RO','SM','RS','SK','SI','ES','SE','CH','TR','UA','GB']) AS t(iso)
ON CONFLICT (iso, flag, admin1_code) DO UPDATE
SET source = EXCLUDED.source, as_of = EXCLUDED.as_of, notes = EXCLUDED.notes;
