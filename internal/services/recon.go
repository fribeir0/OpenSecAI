// services/scan.go
package services

import (
    "log"
    "os/exec"
    "strconv"
    "strings"
    "fmt"

    "go-recon-ai-modular/internal/models"
)

func RunSubfinder(domain string) []string {
    log.Printf("[DEBUG] Executando Subfinder para %s", domain)
    out, err := exec.Command("subfinder", "-d", domain, "-silent").Output()
    if err != nil {
        log.Printf("[ERROR] Subfinder falhou: %v", err)
        return nil
    }
    output := strings.TrimSpace(string(out))
    log.Printf("[DEBUG] Subfinder output bruto:\n%s", output)
    if output == "" {
        return nil
    }
    return strings.Split(output, "\n")
}

func RunNaabu(target string, ports []string) []int {
    args := []string{"-host", target, "-silent", "-timeout", "1000", "-retries", "1", "-rate", "1000"}
    if len(ports) > 0 {
        args = append(args, "-p", strings.Join(ports, ","))
    } else {
        args = append(args, "--top-ports", "100")
    }

    log.Printf("[DEBUG] Executando Naabu para %s com args: %v", target, args)
    out, err := exec.Command("naabu", args...).Output()
    if err != nil {
        log.Printf("[ERROR] Naabu falhou: %v", err)
        return nil
    }
    log.Printf("[DEBUG] Naabu output bruto:\n%s", out)

    var results []int
    lines := strings.Split(string(out), "\n")
    for _, line := range lines {
        parts := strings.Split(line, ":")
        if len(parts) == 2 {
            if p, err := strconv.Atoi(parts[1]); err == nil {
                results = append(results, p)
            }
        }
    }
    return results
}

func RunNaabuCIDR(cidr string, ports []string) map[string][]int {
    args := []string{"-host", cidr, "-silent", "-timeout", "1000", "-retries", "1", "-rate", "1000"}
    if len(ports) > 0 {
        args = append(args, "-p", strings.Join(ports, ","))
    } else {
        args = append(args, "--top-ports", "100")
    }

    log.Printf("[DEBUG] Executando Naabu (CIDR) para %s com args: %v", cidr, args)
    out, err := exec.Command("naabu", args...).Output()
    if err != nil {
        log.Printf("[ERROR] Naabu CIDR falhou: %v", err)
        return nil
    }
    log.Printf("[DEBUG] Naabu CIDR output bruto:\n%s", out)

    result := make(map[string][]int)
    lines := strings.Split(string(out), "\n")
    for _, line := range lines {
        parts := strings.Split(line, ":")
        if len(parts) == 2 {
            ip := parts[0]
            port, err := strconv.Atoi(parts[1])
            if err == nil {
                result[ip] = append(result[ip], port)
            }
        }
    }
    return result
}

func RunNmap(target string, ports []int) []models.PortService {
    if len(ports) == 0 {
        return nil
    }
    portsStr := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(ports)), ","), "[]")
    log.Printf("[DEBUG] Executando Nmap para %s nas portas: %v", target, portsStr)
    out, err := exec.Command("nmap", "-p", portsStr, "-sV", "-Pn", target).Output()
    if err != nil {
        log.Printf("[ERROR] Nmap falhou: %v", err)
        return nil
    }
    log.Printf("[DEBUG] Nmap output bruto:\n%s", out)

    var results []models.PortService
    lines := strings.Split(string(out), "\n")
    for _, line := range lines {
        fields := strings.Fields(line)
        if len(fields) >= 4 && strings.Contains(fields[0], "/tcp") && fields[1] == "open" {
            portStr := strings.Split(fields[0], "/")[0]
            port, err := strconv.Atoi(portStr)
            if err != nil {
                continue
            }
            service := fields[2]
            version := strings.Join(fields[3:], " ")
            results = append(results, models.PortService{
                Port:     port,
                Protocol: "tcp",
                Service:  service,
                Version:  version,
            })
        }
    }
    return results
}
