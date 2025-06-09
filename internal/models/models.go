package models

type CVEInfo struct {
    ID     string  `json:"id"`
    CVSS   float64 `json:"cvss"`
    Desc   string  `json:"description"`
    Link   string  `json:"link"`
}

type PortService struct {
    Port     int       `json:"port"`
    Protocol string    `json:"protocol"`
    Service  string    `json:"service"`
    Version  string    `json:"version"`
    CVEs     []CVEInfo `json:"cves,omitempty"`
}

type HostResult struct {
    Host     string             `json:"host"`
    MAC      string             `json:"mac,omitempty"`
    OS       string             `json:"os,omitempty"`
    Ports    []PortService      `json:"ports"`
    Analysis map[string]interface{} `json:"analysis,omitempty"`
}


type ReconRequest struct {
    Target string   `json:"target"`
    Ports  []string `json:"ports,omitempty"`
}
