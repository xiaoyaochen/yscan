package gonmap

const (
	Closed     Status = 0x00001
	Open              = 0x00002
	Matched           = 0x00003
	NotMatched        = 0x00004
	Unknown           = 0x00005
)

type Status int

func (s Status) String() string {
	switch s {
	case Closed:
		return "Closed"
	case Open:
		return "Open"
	case Matched:
		return "Matched"
	case NotMatched:
		return "NotMatched"
	case Unknown:
		return "Unknown"
	default:
		return "Unknown"
	}
}

type Response struct {
	Raw         string       `json:"raw"`
	TLS         bool         `json:"tls"`
	FingerPrint *FingerPrint `json:"finger_print"`
}

var dnsResponse = Response{Raw: "DnsServer", TLS: false,
	FingerPrint: &FingerPrint{
		Service: "dns",
	},
}
