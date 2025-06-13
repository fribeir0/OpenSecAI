package models

type Vulnerability struct {
    ID          string  `json:"id"`          
    Source      string  `json:"source"`       
    Link        string  `json:"link"`         
    Description string  `json:"description"` 
    CVSS        float64 `json:"cvss"`        
}

type CveDetail struct {
	Summary string  `json:"summary"`
	Cvss    float64 `json:"cvss"`
}

type PortService struct {
    Port     int       `json:"port"`
    Protocol string    `json:"protocol"`
    Service  string    `json:"service"`
    Version  string    `json:"version"`
}

type HostResult struct {
    Host     string             `json:"host"`
    MAC      string             `json:"mac,omitempty"`
    OS       string             `json:"os,omitempty"`
    Ports    []PortService      `json:"ports"`
    Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}


type ReconRequest struct {
    Target string   `json:"target"`
    Ports  []string `json:"ports,omitempty"`
}
