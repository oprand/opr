package aggregator

import (
	"github.com/oprand/opr/internal/opconst"
	"testing"

	whoisdb_store "github.com/oprand/opr/store/postgres/whoisdb"
)

func TestIsFileHealthy(t *testing.T) {
	tests := []struct {
		name               string
		savedRecordsCount  map[opconst.RecordType]int64
		parsedRecordsCount map[opconst.RecordType]int64
		recordTypeAccepted []opconst.RecordType
		expected           bool
	}{
		{
			name:               "Empty saved records",
			savedRecordsCount:  map[opconst.RecordType]int64{},
			parsedRecordsCount: map[opconst.RecordType]int64{opconst.RecordTypeAutNum: 1},
			recordTypeAccepted: []opconst.RecordType{opconst.RecordTypeAutNum},
			expected:           false,
		},
		{
			name: "Healthy records",
			savedRecordsCount: map[opconst.RecordType]int64{
				opconst.RecordTypeAutNum: 1,
			},
			parsedRecordsCount: map[opconst.RecordType]int64{
				opconst.RecordTypeAutNum: 1,
			},
			recordTypeAccepted: []opconst.RecordType{opconst.RecordTypeAutNum, opconst.RecordTypeInetNum},
			expected:           true,
		},
		{
			name: "Unhealthy records",
			savedRecordsCount: map[opconst.RecordType]int64{
				opconst.RecordTypeAutNum: 2,
			},
			parsedRecordsCount: map[opconst.RecordType]int64{
				opconst.RecordTypeAutNum: 3,
			},
			recordTypeAccepted: []opconst.RecordType{opconst.RecordTypeAutNum},
			expected:           false,
		},
		{
			name: "Missing record type in saved",
			savedRecordsCount: map[opconst.RecordType]int64{
				opconst.RecordTypeInetNum: 1,
			},
			parsedRecordsCount: map[opconst.RecordType]int64{
				opconst.RecordTypeAutNum: 1,
			},
			recordTypeAccepted: []opconst.RecordType{opconst.RecordTypeAutNum},
			expected:           false,
		},
		{
			name: "as-set as-block irt healthy after upsert",
			savedRecordsCount: map[opconst.RecordType]int64{
				opconst.RecordTypeAsSet:   2,
				opconst.RecordTypeAsBlock: 1,
				opconst.RecordTypeIrt:     1,
			},
			parsedRecordsCount: map[opconst.RecordType]int64{
				opconst.RecordTypeAsSet:   2,
				opconst.RecordTypeAsBlock: 1,
				opconst.RecordTypeIrt:     1,
			},
			recordTypeAccepted: []opconst.RecordType{
				opconst.RecordTypeAsSet,
				opconst.RecordTypeAsBlock,
				opconst.RecordTypeIrt,
			},
			expected: true,
		},
		{
			name: "as-set parsed but not yet in saved counts",
			savedRecordsCount: map[opconst.RecordType]int64{
				opconst.RecordTypeAutNum: 10,
			},
			parsedRecordsCount: map[opconst.RecordType]int64{
				opconst.RecordTypeAsSet: 2,
			},
			recordTypeAccepted: []opconst.RecordType{opconst.RecordTypeAsSet},
			expected:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsFileHealthy(tt.savedRecordsCount, tt.parsedRecordsCount, tt.recordTypeAccepted)
			if result != tt.expected {
				t.Errorf("IsFileHealthy() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestIsWhoisDBRecordValidAsSetAsBlockIrt(t *testing.T) {
	src := "APNIC"

	tests := []struct {
		name   string
		record whoisdb_store.WhoisRecord
		want   bool
	}{
		{
			name:   "as-set name and source",
			record: &whoisdb_store.WhoisAsSet{AsSet: "AS-CLOUDFLARE", Source: &src},
			want:   true,
		},
		{
			name:   "as-set missing source",
			record: &whoisdb_store.WhoisAsSet{AsSet: "AS-CLOUDFLARE"},
			want:   false,
		},
		{
			name:   "as-set missing name",
			record: &whoisdb_store.WhoisAsSet{Source: &src},
			want:   false,
		},
		{
			name:   "as-block start leq end and source",
			record: &whoisdb_store.WhoisAsBlock{AsnStart: 37945, AsnEnd: 37950, Source: &src},
			want:   true,
		},
		{
			name:   "as-block single asn",
			record: &whoisdb_store.WhoisAsBlock{AsnStart: 37945, AsnEnd: 37945, Source: &src},
			want:   true,
		},
		{
			name:   "as-block inverted",
			record: &whoisdb_store.WhoisAsBlock{AsnStart: 37950, AsnEnd: 37945, Source: &src},
			want:   false,
		},
		{
			name:   "as-block missing source",
			record: &whoisdb_store.WhoisAsBlock{AsnStart: 37945, AsnEnd: 37950},
			want:   false,
		},
		{
			name:   "as-block unparsed zeros",
			record: &whoisdb_store.WhoisAsBlock{Source: &src},
			want:   false,
		},
		{
			name:   "irt name and source",
			record: &whoisdb_store.WhoisIrt{Irt: "IRT-APNICRANDNET-AU", Source: &src},
			want:   true,
		},
		{
			name:   "irt missing source",
			record: &whoisdb_store.WhoisIrt{Irt: "IRT-APNICRANDNET-AU"},
			want:   false,
		},
		{
			name:   "irt missing name",
			record: &whoisdb_store.WhoisIrt{Source: &src},
			want:   false,
		},
		{
			name:   "nil record",
			record: nil,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsWhoisDBRecordValid(tt.record)
			if got != tt.want {
				t.Errorf("IsWhoisDBRecordValid() = %v, want %v", got, tt.want)
			}
		})
	}
}
