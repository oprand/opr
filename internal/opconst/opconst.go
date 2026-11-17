package opconst

type RecordType string

const RecordTypeAutNum RecordType = "autnum"
const RecordTypeInetNum RecordType = "inetnum"
const RecordTypeInet6Num RecordType = "inet6num"
const RecordTypeOrg RecordType = "organization"
const RecordTypeRole RecordType = "role"
const RecordTypePerson RecordType = "person"
const RecordTypeRoute RecordType = "route"
const RecordTypeRoute6 RecordType = "route6"
const RecordTypeAsSet RecordType = "as-set"
const RecordTypeAsBlock RecordType = "as-block"
const RecordTypeIrt RecordType = "irt"

const INVALID_RPKI_MAX_LENGTH_REASON = "At least one VRP Covers the Route Prefix, but the Route Prefix length is greater than the maximum length allowed by VRP(s) matching this route origin ASN"
const INVALID_RPKI_AS_REASON = "At least one VRP Covers the Route Prefix, but no VRP ASN matches the route origin ASN"

const ARIN string = "ARIN"
const AFRINIC string = "AFRINIC"
const APNIC string = "APNIC"
const RIPE string = "RIPE"
const LACNIC string = "LACNIC"
const JPNIC string = "JPNIC"
const KRNIC string = "KRNIC"
const TWNIC string = "TWNIC"

const RDAP_ROLE_REGISTRANT string = "registrant"
const RDAP_ROLE_ABUSE string = "abuse"
const RDAP_ROLE_ADMIN string = "administrative"
const RDAP_ROLE_TECH string = "technical"
const RDAP_ROLE_NOC string = "noc"
const RDAP_ROLE_ROUTING string = "routing"

// const USER_AGENT string = "opr/1.0; (+http://oprand.com/registry/bot.html)"
const USER_AGENT string = "Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/42.0"

var RegistryRDAPEndpoints = map[string]string{
	ARIN:    "https://rdap.arin.net/registry",
	AFRINIC: "https://rdap.afrinic.net/rdap",
	APNIC:   "https://rdap.apnic.net",
	RIPE:    "https://rdap.db.ripe.net",
	LACNIC:  "https://rdap.lacnic.net/rdap",
}

// RegistroBRRDAPEndpoint is NIC.br RDAP for Brazilian LACNIC resources.
// Unlike RegistryRDAPEndpoints[LACNIC], there is no /rdap path suffix.
// Mexico has no public IP/ASN RDAP; only BR is routed here.
const RegistroBRRDAPEndpoint = "https://rdap.registro.br"

type RDAPEntityType uint8

const (
	// Request or Response
	None RDAPEntityType = iota
	ASN
	Prefix
	IP
	DomainName
	// Request only
	Organization
	Country
	EmailDomainName
)

var Webmails = map[string]struct{}{
	// US
	"gmail.com":    {},
	"aol.com":      {},
	"hotmail.com":  {},
	"outlook.com":  {},
	"icloud.com":   {},
	"me.com":       {},
	"yahoo.com":    {},
	"fastmail.com": {},
	"mail.com":     {},
	"hey.com":      {},
	"lycos.com":    {},
	// RU
	"mail.ru":   {},
	"yandex.ru": {},
	// DE
	"gmx.com":      {},
	"gmx.de":       {},
	"posteo.de":    {},
	"posteo.net":   {},
	"tutanota.com": {},
	"tutanota.de":  {},
	"tutamail.com": {},
	"tuta.io":      {},
	"keemail.me":   {},
	// CH
	"protonmail.com": {},
	"protonmail.ch":  {},
	"pm.me":          {},
	"proton.me":      {},
	// FR
	"laposte.net": {},
	// IN
	"rediffmail.com": {},
	// BE
	"mailfence.com": {},
	// CN
	"126.com":    {},
	"163.com":    {},
	"sina.com":   {},
	"qq.com":     {},
	"vip.qq.com": {},
	// BR
	"numeracao.registro.br": {},
	// KR
	"naver.com": {},
}

var CountryCode = map[string]string{
	"AD": "Andorra",
	"AE": "United Arab Emirates",
	"AF": "Afghanistan",
	"AG": "Antigua and Barbuda",
	"AI": "Anguilla",
	"AL": "Albania",
	"AM": "Armenia",
	"AO": "Angola",
	"AQ": "Antarctica",
	"AR": "Argentina",
	"AS": "American Samoa",
	"AT": "Austria",
	"AU": "Australia",
	"AW": "Aruba",
	"AX": "Aland Islands",
	"AZ": "Azerbaijan",
	"BA": "Bosnia and Herzegovina",
	"BB": "Barbados",
	"BD": "Bangladesh",
	"BE": "Belgium",
	"BF": "Burkina Faso",
	"BG": "Bulgaria",
	"BH": "Bahrain",
	"BI": "Burundi",
	"BJ": "Benin",
	"BL": "Saint Barthelemy",
	"BM": "Bermuda",
	"BN": "Brunei",
	"BO": "Bolivia",
	"BQ": "Bonaire, Saint Eustatius and Saba ",
	"BR": "Brazil",
	"BS": "Bahamas",
	"BT": "Bhutan",
	"BV": "Bouvet Island",
	"BW": "Botswana",
	"BY": "Belarus",
	"BZ": "Belize",
	"CA": "Canada",
	"CC": "Cocos Islands",
	"CD": "Democratic Republic of the Congo",
	"CF": "Central African Republic",
	"CG": "Republic of the Congo",
	"CH": "Switzerland",
	"CI": "Ivory Coast",
	"CK": "Cook Islands",
	"CL": "Chile",
	"CM": "Cameroon",
	"CN": "China",
	"CO": "Colombia",
	"CR": "Costa Rica",
	"CU": "Cuba",
	"CV": "Cabo Verde",
	"CW": "Curacao",
	"CX": "Christmas Island",
	"CY": "Cyprus",
	"CZ": "Czechia",
	"DE": "Germany",
	"DJ": "Djibouti",
	"DK": "Denmark",
	"DM": "Dominica",
	"DO": "Dominican Republic",
	"DZ": "Algeria",
	"EC": "Ecuador",
	"EE": "Estonia",
	"EG": "Egypt",
	"EH": "Western Sahara",
	"ER": "Eritrea",
	"ES": "Spain",
	"EU": "European Union", // Europe
	"ET": "Ethiopia",
	"FI": "Finland",
	"FJ": "Fiji",
	"FK": "Falkland Islands",
	"FM": "Micronesia",
	"FO": "Faroe Islands",
	"FR": "France",
	"GA": "Gabon",
	"GB": "United Kingdom",
	"GD": "Grenada",
	"GE": "Georgia",
	"GF": "French Guiana",
	"GG": "Guernsey",
	"GH": "Ghana",
	"GI": "Gibraltar",
	"GL": "Greenland",
	"GM": "Gambia",
	"GN": "Guinea",
	"GP": "Guadeloupe",
	"GQ": "Equatorial Guinea",
	"GR": "Greece",
	"GS": "South Georgia and the South Sandwich Islands",
	"GT": "Guatemala",
	"GU": "Guam",
	"GW": "Guinea-Bissau",
	"GY": "Guyana",
	"HK": "Hong Kong",
	"HM": "Heard Island and McDonald Islands",
	"HN": "Honduras",
	"HR": "Croatia",
	"HT": "Haiti",
	"HU": "Hungary",
	"ID": "Indonesia",
	"IE": "Ireland",
	"IL": "Israel",
	"IM": "Isle of Man",
	"IN": "India",
	"IO": "British Indian Ocean Territory",
	"IQ": "Iraq",
	"IR": "Iran",
	"IS": "Iceland",
	"IT": "Italy",
	"JE": "Jersey",
	"JM": "Jamaica",
	"JO": "Jordan",
	"JP": "Japan",
	"KE": "Kenya",
	"KG": "Kyrgyzstan",
	"KH": "Cambodia",
	"KI": "Kiribati",
	"KM": "Comoros",
	"KN": "Saint Kitts and Nevis",
	"KP": "North Korea",
	"KR": "South Korea",
	"XK": "Kosovo",
	"KW": "Kuwait",
	"KY": "Cayman Islands",
	"KZ": "Kazakhstan",
	"LA": "Laos",
	"LB": "Lebanon",
	"LC": "Saint Lucia",
	"LI": "Liechtenstein",
	"LK": "Sri Lanka",
	"LR": "Liberia",
	"LS": "Lesotho",
	"LT": "Lithuania",
	"LU": "Luxembourg",
	"LV": "Latvia",
	"LY": "Libya",
	"MA": "Morocco",
	"MC": "Monaco",
	"MD": "Moldova",
	"ME": "Montenegro",
	"MF": "Saint Martin",
	"MG": "Madagascar",
	"MH": "Marshall Islands",
	"MK": "North Macedonia",
	"ML": "Mali",
	"MM": "Myanmar",
	"MN": "Mongolia",
	"MO": "Macao",
	"MP": "Northern Mariana Islands",
	"MQ": "Martinique",
	"MR": "Mauritania",
	"MS": "Montserrat",
	"MT": "Malta",
	"MU": "Mauritius",
	"MV": "Maldives",
	"MW": "Malawi",
	"MX": "Mexico",
	"MY": "Malaysia",
	"MZ": "Mozambique",
	"NA": "Namibia",
	"NC": "New Caledonia",
	"NE": "Niger",
	"NF": "Norfolk Island",
	"NG": "Nigeria",
	"NI": "Nicaragua",
	"NL": "Netherlands",
	"NO": "Norway",
	"NP": "Nepal",
	"NR": "Nauru",
	"NU": "Niue",
	"NZ": "New Zealand",
	"OM": "Oman",
	"PA": "Panama",
	"PE": "Peru",
	"PF": "French Polynesia",
	"PG": "Papua New Guinea",
	"PH": "Philippines",
	"PK": "Pakistan",
	"PL": "Poland",
	"PM": "Saint Pierre and Miquelon",
	"PN": "Pitcairn",
	"PR": "Puerto Rico",
	"PS": "Palestinian Territory",
	"PT": "Portugal",
	"PW": "Palau",
	"PY": "Paraguay",
	"QA": "Qatar",
	"RE": "Reunion",
	"RO": "Romania",
	"RS": "Serbia",
	"RU": "Russia",
	"RW": "Rwanda",
	"SA": "Saudi Arabia",
	"SB": "Solomon Islands",
	"SC": "Seychelles",
	"SD": "Sudan",
	"SS": "South Sudan",
	"SE": "Sweden",
	"SG": "Singapore",
	"SH": "Saint Helena",
	"SI": "Slovenia",
	"SJ": "Svalbard and Jan Mayen",
	"SK": "Slovakia",
	"SL": "Sierra Leone",
	"SM": "San Marino",
	"SN": "Senegal",
	"SO": "Somalia",
	"SR": "Suriname",
	"ST": "Sao Tome and Principe",
	"SV": "El Salvador",
	"SX": "Sint Maarten",
	"SY": "Syria",
	"SZ": "Eswatini",
	"TC": "Turks and Caicos Islands",
	"TD": "Chad",
	"TF": "French Southern Territories",
	"TG": "Togo",
	"TH": "Thailand",
	"TJ": "Tajikistan",
	"TK": "Tokelau",
	"TL": "Timor Leste",
	"TM": "Turkmenistan",
	"TN": "Tunisia",
	"TO": "Tonga",
	"TR": "Turkey",
	"TT": "Trinidad and Tobago",
	"TV": "Tuvalu",
	"TW": "Taiwan",
	"TZ": "Tanzania",
	"UA": "Ukraine",
	"UG": "Uganda",
	"UM": "United States Minor Outlying Islands",
	"US": "United States",
	"UY": "Uruguay",
	"UZ": "Uzbekistan",
	"VA": "Vatican",
	"VC": "Saint Vincent and the Grenadines",
	"VE": "Venezuela",
	"VG": "British Virgin Islands",
	"VI": "U.S. Virgin Islands",
	"VN": "Vietnam",
	"VU": "Vanuatu",
	"WF": "Wallis and Futuna",
	"WS": "Samoa",
	"YE": "Yemen",
	"YT": "Mayotte",
	"ZA": "South Africa",
	"ZM": "Zambia",
	"ZW": "Zimbabwe",
	"CS": "Serbia and Montenegro",
	"AN": "Netherlands Antilles",
}
