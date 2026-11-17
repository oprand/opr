package registry

// import (
// 	"io/ioutil"
// 	"github.com/oprand/opr/store/postgres"
// 	"testing"
// 	"time"

// 	"github.com/openrdap/rdap"
// 	"github.com/stretchr/testify/assert"
// )

// func TestParseLacnicRdapAsResponse(t *testing.T) {

// 	timeAS1296Creation, _ := time.Parse(time.RFC3339, "1991-06-11T12:00:00Z")
// 	timeAS1296LastModified, _ := time.Parse(time.RFC3339, "1991-06-12T12:00:00Z")
// 	timeAS270482Creation, _ := time.Parse(time.RFC3339, "2020-03-11T12:18:03Z")
// 	timeAS270482LastModified, _ := time.Parse(time.RFC3339, "2020-03-11T12:18:03Z")

// 	testCases := map[string]postgres.AsnInfo{
// 		"./testdata/lacnic/AS1296.json": {
// 			Handle: "AS1296", CreatedAt: &timeAS1296Creation, LastModifiedAt: &timeAS1296LastModified, Type: "DIRECT ALLOCATION",
// 			RegistrantHandle: "CL-UOCH1-LACNIC", RegistrantName: "University of Chili", RegistrantAddress: "Fac. de Ciencias Fisicas y Matematicas\nBlanco Encalada 2120\nSantiago\nCL",
// 			RegistrantType: "org",
// 			AdminHandle:    "VU-ARIN", AdminName: "Vladimir Ulyashin", AdminType: "individual", AdminEmail: "vlad@bgrg.com", AdminPhone: "925-253-0942",
// 			AdminAddress: "HEFFLER, RADETECH & SAITTA\n1515 MARKET ST\nUS",
// 		},
// 		"./testdata/lacnic/AS270482.json": {
// 			Handle: "270482", CreatedAt: &timeAS270482Creation, LastModifiedAt: &timeAS270482LastModified, Type: "DIRECT ALLOCATION", Country: "BR", Name: "ASN270482",
// 			RegistrantHandle: "22862271000199", RegistrantName: "Raiden Telecom", RegistrantAddress: "BR", RegistrantType: "org",
// 			AdminHandle: "SAFSI147", AdminName: "samuel de Figueiredo Silva", AdminType: "individual", AdminEmail: "samuel.figueiredo.silva@gmail.com",
// 			AdminAddress: "BR",
// 			AbuseHandle:  "SAFSI147", AbuseName: "samuel de Figueiredo Silva", AbuseEmail: "samuel.figueiredo.silva@gmail.com", AbuseAddress: "BR",
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
