package registry

// import (
// 	"io/ioutil"
// 	"github.com/oprand/opr/store/postgres"
// 	"testing"
// 	"time"

// 	"github.com/openrdap/rdap"
// 	"github.com/stretchr/testify/assert"
// )

// func TestParseAfrinicRdapAsResponse(t *testing.T) {

// 	timeAS6968Creation, _ := time.Parse(time.RFC3339, "2005-02-21T15:31:00Z")
// 	timeAS6968LastModified, _ := time.Parse(time.RFC3339, "2017-01-24T08:25:00Z")
// 	timeAS328703Creation, _ := time.Parse(time.RFC3339, "2020-07-16T19:31:00Z")

// 	testCases := map[string]postgres.AsnInfo{
// 		"./testdata/afrinic/AS6968.json": {
// 			Handle: "AS6968", CreatedAt: &timeAS6968Creation, LastModifiedAt: &timeAS6968LastModified, Name: "ORG-US7-AFRINIC",
// 			RegistrantHandle: "ORG-US7-AFRINIC", RegistrantName: "ZA CENTRAL REGISTRY NPC", RegistrantAddress: "P O Box 4620\nHalfway House 1685",
// 			RegistrantType: "org", RegistrantPhone: "tel:+27-11-314-0077", RegistrantEmail: "techsupport@co.za",
// 			AdminHandle: "DKP-AFRINIC", AdminName: "David Peall", AdminType: "individual", AdminEmail: "dkpeall@gmail.com", AdminPhone: "tel:+27-11-314-0077",
// 			AdminAddress: "P O Box 4620\nHalfway House\nGauteng\n1685\nZA\nJohannesburg 1685\nSouth Africa",
// 			TechHandle:   "DKP-AFRINIC",
// 			// AbuseHandle:  "ABUSE5412-ARIN", AbusePhone: "+1-770-857-4700",
// 			// AbuseName: "Abuse", AbuseEmail: "abuse@theice.com", AbuseAddress: "5660 New Northside Dr. NW\nAtlanta\nGA\n30328\nUnited States",
// 		},
// 		"./testdata/afrinic/AS328703.json": {
// 			Handle: "AS328703", CreatedAt: &timeAS328703Creation, LastModifiedAt: &time.Time{}, Name: "ORG-SNI2-AFRINIC",
// 			RegistrantHandle: "ORG-SNI2-AFRINIC", RegistrantName: "Seven Network Inc.", RegistrantAddress: "103 Sham Peng Tong Plaza\nVictoria Mahe",
// 			RegistrantType: "org", RegistrantEmail: "info@seven.network", RegistrantPhone: "tel:+248-4-671-965",
// 			AdminHandle: "MJ20-AFRINIC", AdminName: "Mary Jane", AdminType: "individual", AdminEmail: "ceo@seven.network", AdminPhone: "tel:+248-4-671-965",
// 			AdminAddress: "103 Sham Peng Tong Plaza\nVictoria\nSeychelles",
// 			TechHandle:   "LR11-AFRINIC",
// 			// AbuseHandle:  "NOC2949-ARIN", AbusePhone: "+1-832-463-2100;ext(832)463-2122",
// 			// AbuseName: "Network Operations Center", AbuseEmail: "operations@stratosglobal.com", AbuseAddress: "1201 Louisiana St., Suite 520\nHouston\nTX\n77002\nUnited States",
// 		},
// 	}

// 	for fixturePath, AsnInfoExpected := range testCases {

// 		fixture, err := ioutil.ReadFile(fixturePath)
// 		if err != nil {
// 			t.Fatal(err)
// 		}

// 		decoder := rdap.NewDecoder(fixture)

// 		object, err := decoder.Decode()
// 		if err != nil {
// 			t.Fatal(err)
// 		}

// 		respData, ok := object.(*rdap.Autnum)
// 		if !ok {
// 			t.Fatal("respData is not of type Autnum")
// 			return
// 		}

// 		var asnInfoParsed postgres.AsnInfo
// 		MarshalRdapResponseForAs(respData, &asnInfoParsed)

// 		assert := assert.New(t)

// 		assert.Equal(AsnInfoExpected, asnInfoParsed)

// 	}

// }
