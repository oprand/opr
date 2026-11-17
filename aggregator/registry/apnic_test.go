package registry

// import (
// 	"io/ioutil"
// 	"github.com/oprand/opr/store/postgres"
// 	"testing"
// 	"time"

// 	"github.com/openrdap/rdap"
// 	"github.com/stretchr/testify/assert"
// )

// func TestParseApnicRdapAsResponse(t *testing.T) {

// 	timeAS145715Creation, _ := time.Parse(time.RFC3339, "2021-05-07T01:05:41Z")
// 	timeAS145715LastModified, _ := time.Parse(time.RFC3339, "2021-05-07T01:05:41Z")
// 	timeAS138371Creation, _ := time.Parse(time.RFC3339, "2018-10-24T06:27:42Z")
// 	timeAS138371LastModified, _ := time.Parse(time.RFC3339, "2020-09-03T09:16:08Z")

// 	testCases := map[string]postgres.AsnInfo{
// 		"./testdata/apnic/AS145715.json": {
// 			Handle: "AS145210 - AS145721", CreatedAt: &timeAS145715Creation, LastModifiedAt: &timeAS145715LastModified,
// 			Desc: "China Education and Research Network (CERNET)\nCERNET AS Block for FITI Slices", Country: "CN",
// 			RegistrantHandle: "ORG-CEAR1-AP", RegistrantName: "China Education and Research Network (CERNET)", RegistrantAddress: "FIT 3-220,\nTsinghua University",
// 			RegistrantType: "org", RegistrantEmail: "hostmaster@cernic.net", RegistrantPhone: "+86-10-62785983", RegistrantFax: "+86-10-62785933",
// 			AdminHandle: "CER-AP", AdminName: "CERNET Helpdesk", AdminType: "group", AdminEmail: "helpdesk@cernet.edu.cn", AdminPhone: "+86-10-6278-4049",
// 			AdminAddress: "CERNET Center\nBeijing 100084, China", AdminFax: "+86-10-6278-5933",
// 			TechHandle: "CER-AP",
// 		},
// 		"./testdata/apnic/AS138371.json": {
// 			Handle: "AS138371", Name: "CNGI-QDA-IX-AS-AP", CreatedAt: &timeAS138371Creation, LastModifiedAt: &timeAS138371LastModified,
// 			Desc: "CERNET2 regional IX at Ocean University of China\nCERNET Center\nBeijing 100084, China", Country: "CN",
// 			RegistrantHandle: "ORG-CEAR1-AP", RegistrantName: "China Education and Research Network (CERNET)", RegistrantAddress: "FIT 3-220,\nTsinghua University",
// 			RegistrantType: "org", RegistrantEmail: "hostmaster@cernic.net", RegistrantPhone: "+86-10-62785983", RegistrantFax: "+86-10-62785933",
// 			AdminHandle: "CER-AP", AdminName: "CERNET Helpdesk", AdminType: "group", AdminEmail: "helpdesk@cernet.edu.cn", AdminPhone: "+86-10-6278-4049",
// 			AdminAddress: "CERNET Center\nBeijing 100084, China", AdminFax: "+86-10-6278-5933",
// 			TechHandle:  "CER-AP",
// 			AbuseHandle: "IRT-CERNET-AP", AbuseName: "IRT-CERNET-AP", AbuseEmail: "abuse@cernet.edu.cn", AbuseFax: "+86-10-62785933", AbusePhone: "+86-10-62784301",
// 			AbuseAddress: "Network Research Center,\nMain Bldg, Tsinghua Univ\nBeijing 100084, China",
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
