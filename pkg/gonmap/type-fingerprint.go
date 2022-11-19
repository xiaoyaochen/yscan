package gonmap

type FingerPrint struct {
	ProbeName        string `json:"probe_name"`
	MatchRegexString string `json:"match_regex_string"`

	Service         string `json:"service"`
	ProductName     string `json:"product"`
	Version         string `json:"version"`
	Info            string `json:"info"`
	Hostname        string `json:"hostname"`
	OperatingSystem string `json:"os"`
	DeviceType      string `json:"device_type"`
	//  p/vendorproductname/
	//	v/version/
	//	i/info/
	//	h/hostname/
	//	o/operatingsystem/
	//	d/devicetype/
}
