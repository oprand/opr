package aggregator

import (
	"github.com/oprand/opr/internal/opconst"
	"time"

	whoisdb_store "github.com/oprand/opr/store/postgres/whoisdb"
)

// ComputeSleepDuration computes the sleep duration based on the interval and
// total job duration.
// If the sleep duration is negative, it sets it to 10 minutes.
func ComputeSleepDuration(interval time.Duration, totalJobDuration time.Duration) time.Duration {

	sleepDuration := interval - totalJobDuration
	if sleepDuration < 0 {
		sleepDuration = 10 * time.Minute
	}

	return sleepDuration
}

// IsFileHealthy checks that all parsed records are saved.
// The same number of records (per type) are expected to be saved as parsed.
// We allow for more records to be saved than parsed because some records
// might be saved in a previous run of the same job, or via other means
// (e.g. RDAP crawler).
// TODO: add a way to check only for some record type
func IsFileHealthy(savedRecordsCount, parsedRecordsCount map[opconst.RecordType]int64, recordTypeAccepted []opconst.RecordType) bool {
	if len(savedRecordsCount) == 0 {
		return false
	}

	for _, recordType := range recordTypeAccepted {
		if parsedRecordsCount[recordType] > savedRecordsCount[recordType] {
			return false
		}
	}
	return true
}

// IsWhoisDBRecordValid validates if a whoisdb record is valid for database insertion.
func IsWhoisDBRecordValid(record whoisdb_store.WhoisRecord) bool {

	if record == nil {
		return false
	}

	switch record.GetRecordType() {
	case opconst.RecordTypeAutNum:
		asn, ok := record.(*whoisdb_store.WhoisAutNum)
		if !ok {
			return false
		}
		return asn.AutNum != 0 && asn.Source != nil
	case opconst.RecordTypeInetNum:
		inetnum, ok := record.(*whoisdb_store.WhoisInetNum)
		if !ok {
			return false
		}
		return inetnum.Netblock != nil && inetnum.Source != nil
	case opconst.RecordTypeInet6Num:
		inet6num, ok := record.(*whoisdb_store.WhoisInet6Num)
		if !ok {
			return false
		}
		return inet6num.Netblock != nil && inet6num.Source != nil
	case opconst.RecordTypeOrg:
		org, ok := record.(*whoisdb_store.WhoisOrganization)
		if !ok {
			return false
		}
		return org.Organization != "" && org.Source != nil
	case opconst.RecordTypeRole:
		role, ok := record.(*whoisdb_store.WhoisRole)
		if !ok {
			return false
		}
		return role.NicHdl != "" && role.Source != nil
	case opconst.RecordTypeRoute:
		route, ok := record.(*whoisdb_store.WhoisRoute)
		if !ok {
			return false
		}
		return route.Route != ""
	case opconst.RecordTypeRoute6:
		route6, ok := record.(*whoisdb_store.WhoisRoute6)
		if !ok {
			return false
		}
		return route6.Route6 != ""
	case opconst.RecordTypeAsSet:
		asSet, ok := record.(*whoisdb_store.WhoisAsSet)
		if !ok {
			return false
		}
		return asSet.AsSet != "" && asSet.Source != nil
	case opconst.RecordTypeAsBlock:
		asBlock, ok := record.(*whoisdb_store.WhoisAsBlock)
		if !ok {
			return false
		}
		return asBlock.Source != nil && asBlock.AsnStart != 0 && asBlock.AsnStart <= asBlock.AsnEnd
	case opconst.RecordTypeIrt:
		irt, ok := record.(*whoisdb_store.WhoisIrt)
		if !ok {
			return false
		}
		return irt.Irt != "" && irt.Source != nil
	default:
		return false
	}

}
