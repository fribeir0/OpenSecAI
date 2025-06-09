package models

type ReconRequest struct {
    Target string   `json:"target"`
    Ports  []string `json:"ports,omitempty"`
}

type PortService struct {
    Port     int    `json:"port"`
    Protocol string `json:"protocol"`
    Service  string `json:"service"`
    Version  string `json:"version"`
}

type HostResult struct {
    Host  string        `json:"host"`
    Ports []PortService `json:"ports"`
}