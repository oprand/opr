package registry

// import (
// 	"io/ioutil"
// 	"github.com/oprand/opr/store/postgres"
// 	"testing"
// 	"time"

// 	"github.com/openrdap/rdap"
// 	"github.com/stretchr/testify/assert"
// )

// func TestParseRipeRdapAsResponse(t *testing.T) {

// 	timeAS64461, _ := time.Parse(time.RFC3339, "2021-07-14T12:33:34Z")
// 	timeAS9009, _ := time.Parse(time.RFC3339, "2018-12-19T16:38:38Z")
// 	timeAS212238, _ := time.Parse(time.RFC3339, "2020-12-02T09:57:07Z")
// 	timeAS44141, _ := time.Parse(time.RFC3339, "2019-11-19T07:15:56Z")

// 	testCases := map[string]postgres.AsnInfo{
// 		"./testdata/ripe/AS64461.json": {Handle: "AS64461", Name: "SMARTAVIA-AS", Type: "DIRECT ALLOCATION", LastModifiedAt: &timeAS64461,
// 			TechHandle: "NRAC2-RIPE", RegistrantHandle: "ORG-NRAC1-RIPE", AdminHandle: "NRAC2-RIPE", AbuseHandle: "NRAC2-RIPE", RegistrantEmail: "noc@flysmartavia.com",
// 			AbuseName: "Smartavia Airlines JSC NOC", AbuseEmail: "abuse@flysmartavia.com", AbuseAddress: "4 airport Arkhangelsk, Arkhangelsk, Russia",
// 		},
// 		"./testdata/ripe/AS9009.json": {Handle: "AS9009", Name: "M247", Type: "DIRECT ALLOCATION", LastModifiedAt: &timeAS9009,
// 			TechHandle: "GBXS-RIPE", RegistrantHandle: "ORG-GL37-RIPE", AdminHandle: "GBXS-RIPE", AbuseHandle: "GBXS-RIPE", RegistrantEmail: "nmc@m247.com",
// 			AbuseName: "GLOBALAXS NOC", AbuseEmail: "abuse@m247.ro", AbuseAddress: "1 Ball Green, Cobra Court\nM32 0QT, Manchester - United Kingdom",
// 		},
// 		"./testdata/ripe/AS212238.json": {Handle: "AS212238", Name: "CDNEXT", Type: "DIRECT ALLOCATION", LastModifiedAt: &timeAS212238,
// 			TechHandle: "JP4750-RIPE", RegistrantHandle: "ORG-DL201-RIPE", AdminHandle: "JP4750-RIPE", AbuseHandle: "AC28308-RIPE", RegistrantEmail: "abuse@datacamp.co.uk",
// 			AbuseName: "Abuse Contact", AbuseEmail: "abuse@datacamp.co.uk", AbuseAddress: "Datacamp Limited\nZdenek Cendra\n207 Regent Street\nW1B 3HH\nLondon\nUNITED KINGDOM",
// 		},
// 		"./testdata/ripe/AS44141.json": {Handle: "AS44141", Name: "DEVCLIC-AS", Type: "DIRECT ALLOCATION", LastModifiedAt: &timeAS44141,
// 			TechHandle: "RL885-RIPE", RegistrantHandle: "ORG-DS58-RIPE", AdminHandle: "RL885-RIPE", AbuseHandle: "AR15227-RIPE", RegistrantEmail: "bonjour@devclic.fr",
// 			AbuseName: "Abuse-C Role", AbuseEmail: "abuse@devclic.fr", AbuseAddress: "DEVCLIC\n13 avenue de l'Europe\n67300 SCHILTIGHEIM",
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
// 		// MarshalRdapResponseForAs(respData, &asnInfoParsed)

// 		assert := assert.New(t)

// 		assert.Equal(AsnInfoExpected, asnInfoParsed)

// 	}

// }

// func TestParseRipeRdapRegistrantResponse(t *testing.T) {

// 	// testCases := map[string]postgres.AsnInfo{
// 	// 	"./testdata/ripe/ORG-DS58-RIPE.json": {
// 	// 		RegistrantName:    "DEVCLIC SARL",
// 	// 		RegistrantType:    "org",
// 	// 		RegistrantAddress: "20, allée des Anémones\n57530\nCOURCELLES-CHAUSSY\nFRANCE",
// 	// 		RegistrantPhone:   "+33357756146",
// 	// 		RegistrantFax:     "+33357756147",
// 	// 		RegistrantEmail:   "contact@devclic.fr",
// 	// 	},
// 	// }

// 	// for fixturePath, AsnInfoExpected := range testCases {

// 	// fixture, err := ioutil.ReadFile(fixturePath)
// 	// if err != nil {
// 	// 	t.Fatal(err)
// 	// }

// 	// decoder := rdap.NewDecoder(fixture)

// 	// object, err := decoder.Decode()
// 	// if err != nil {
// 	// 	t.Fatal(err)
// 	// }

// 	// respData, ok := object.(*rdap.Entity)
// 	// if !ok {
// 	// 	t.Fatal("respData is not of type Entity")
// 	// 	return
// 	// }

// 	// var asnInfoParsed postgres.AsnInfo
// 	// MarshalRdapResponseForEntity(respData, &asnInfoParsed)

// 	// assert := assert.New(t)

// 	// assert.Equal(AsnInfoExpected, asnInfoParsed)

// 	// }

// }
