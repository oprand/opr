package registry

// import (
// 	"io/ioutil"
// 	"github.com/oprand/opr/store/postgres"
// 	"testing"
// 	"time"

// 	"github.com/openrdap/rdap"
// 	"github.com/stretchr/testify/assert"
// )

// func TestParseArinRdapAsResponse(t *testing.T) {

// 	timeAS64461Creation, _ := time.Parse(time.RFC3339, "2016-05-18T12:44:13-04:00")
// 	timeAS64461LastModified, _ := time.Parse(time.RFC3339, "2022-06-14T14:52:33-04:00")
// 	timeAS40575Creation, _ := time.Parse(time.RFC3339, "2008-02-05T14:09:03-05:00")
// 	timeAS40575LastModified, _ := time.Parse(time.RFC3339, "2012-03-02T08:03:18-05:00")

// 	testCases := map[string]postgres.AsnInfo{
// 		"./testdata/arin/AS64255.json": {Handle: "AS64255", Name: "EM-888", CreatedAt: &timeAS64461Creation, LastModifiedAt: &timeAS64461LastModified,
// 			RegistrantHandle: "IE-217", RegistrantName: "Intercontinental Exchange, Inc.", RegistrantAddress: "5660 New Northside Dr. NW\nAtlanta\nGA\n30328\nUnited States",
// 			RegistrantType: "org",
// 			AdminHandle:    "INT8-ARIN", AdminName: "ICE Network Team", AdminType: "group", AdminEmail: "riradmin@theice.com", AdminPhone: "+1-770-738-2101",
// 			AdminAddress: "5660 New Northside Dr. NW\nAtlanta\nGA\n30328\nUnited States",
// 			TechHandle:   "INT8-ARIN",
// 			AbuseHandle:  "ABUSE5412-ARIN", AbusePhone: "+1-770-857-4700",
// 			AbuseName: "Abuse", AbuseEmail: "abuse@theice.com", AbuseAddress: "5660 New Northside Dr. NW\nAtlanta\nGA\n30328\nUnited States",
// 		},
// 		"./testdata/arin/AS40575.json": {Handle: "AS40575", Name: "STRATOS", CreatedAt: &timeAS40575Creation, LastModifiedAt: &timeAS40575LastModified,
// 			RegistrantHandle: "SOS-86", RegistrantName: "Stratos Global Communications", RegistrantAddress: "34 GLENCOE DRIVE\nSt. John's\nNL\nA1C 5X3\nCanada",
// 			RegistrantType: "org",
// 			AdminHandle:    "NOC2949-ARIN", AdminName: "Network Operations Center", AdminType: "group", AdminEmail: "operations@stratosglobal.com", AdminPhone: "+1-832-463-2100;ext(832)463-2122",
// 			AdminAddress: "1201 Louisiana St., Suite 520\nHouston\nTX\n77002\nUnited States",
// 			TechHandle:   "TECHN645-ARIN",
// 			AbuseHandle:  "NOC2949-ARIN", AbusePhone: "+1-832-463-2100;ext(832)463-2122",
// 			AbuseName: "Network Operations Center", AbuseEmail: "operations@stratosglobal.com", AbuseAddress: "1201 Louisiana St., Suite 520\nHouston\nTX\n77002\nUnited States",
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
