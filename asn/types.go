package asn

import "time"

type FetchAsnParams struct {
	Json bool
	Ip   bool
	Cidr bool
}

type AsnResponse []AsnResponseItem

type AsnResponseItem struct {
	Input  string   `json:"input"`
	Error  string   `json:"error"`
	Output *AsnInfo `json:"output"`
}

type RelatedAsnInfo struct {
	Asn       uint32     `json:"asn"`
	RirName   *string    `json:"rir_name"`
	Name      string     `json:"name"`
	Handle    string     `json:"handle"`
	CreatedAt *time.Time `json:"allocated_at"`
	Ipv4Count *uint64    `json:"ipv4_count"`
}

type AsnInfo struct {
	Asn            uint32     `json:"asn"`
	Name           string     `json:"name"`
	Status         *string    `json:"status"`
	RirUrl         *string    `json:"rir_url"`
	Handle         string     `json:"handle"`
	Domain         *string    `json:"domain"`
	RirName        *string    `json:"rir_name"`
	Type           string     `json:"type"`
	Desc           string     `json:"description"`
	Country        string     `json:"country"`
	CreatedAt      *time.Time `json:"allocated_at"`
	LastModifiedAt *time.Time `json:"last_updated_at"`
	Ipv4Ranges     *[]string  `json:"ipv4_ranges"`
	Ipv4Count      *uint64    `json:"ipv4_count"`
	Ipv6Ranges     *[]string  `json:"ipv6_ranges"`
	//
	TechType    string `json:"tech_type"`
	TechHandle  string `json:"tech_handle"`
	TechName    string `json:"tech_name"`
	TechEmail   string `json:"tech_email"`
	TechPhone   string `json:"tech_phone"`
	TechAddress string `json:"tech_address"`
	TechCountry string `json:"tech_country"`
	TechFax     string `json:"tech_fax"`
	//
	RegistrantType    string `json:"registrant_type"`
	RegistrantHandle  string `json:"registrant_handle"`
	RegistrantName    string `json:"registrant_name"`
	RegistrantEmail   string `json:"registrant_email"`
	RegistrantPhone   string `json:"registrant_phone"`
	RegistrantAddress string `json:"registrant_address"`
	RegistrantCountry string `json:"registrant_country"`
	RegistrantFax     string `json:"registrant_fax"`
	//
	AbuseType    string `json:"abuse_type"`
	AbuseHandle  string `json:"abuse_handle"`
	AbuseName    string `json:"abuse_name"`
	AbuseEmail   string `json:"abuse_email"`
	AbusePhone   string `json:"abuse_phone"`
	AbuseAddress string `json:"abuse_address"`
	AbuseCountry string `json:"abuse_country"`
	AbuseFax     string `json:"abuse_fax"`
	//
	AdminType    string `json:"admin_type"`
	AdminHandle  string `json:"admin_handle"`
	AdminName    string `json:"admin_name"`
	AdminAddress string `json:"admin_address"`
	AdminPhone   string `json:"admin_phone"`
	AdminEmail   string `json:"admin_email"`
	AdminCountry string `json:"admin_country"`
	AdminFax     string `json:"admin_fax"`
	// N.O.C.: Network Operation Center
	NocType    string `json:"noc_type"`
	NocHandle  string `json:"noc_handle"`
	NocName    string `json:"noc_name"`
	NocAddress string `json:"noc_address"`
	NocPhone   string `json:"noc_phone"`
	NocEmail   string `json:"noc_email"`
	NocCountry string `json:"noc_country"`
	NocFax     string `json:"noc_fax"`
	// Related Asn
	ShareRegistrantHandle []RelatedAsnInfo `json:"share_registrant_handle"`
	ShareAdminHandle      []RelatedAsnInfo `json:"share_admin_handle"`
	ShareAbuseHandle      []RelatedAsnInfo `json:"share_abuse_handle"`
	ShareTechHandle       []RelatedAsnInfo `json:"share_tech_handle"`
}
