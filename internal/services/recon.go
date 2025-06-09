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

func RunNmapFast(target string, ports []int) models.HostResult {
    var result models.HostResult
    result.Host = target

    if len(ports) == 0 {
        return result
    }

    portsStr := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(ports)), ","), "[]")
    cmd := exec.Command("nmap", "-T4", "--max-retries", "1", "--host-timeout", "30s", "-p", portsStr, "-sV", "-O", "-Pn", target)

    out, err := cmd.Output()
    if err != nil {
        log.Printf("[ERROR] NmapFast falhou para %s: %v", target, err)
        return result
    }

    lines := strings.Split(string(out), "\n")
    for _, line := range lines {
        line = strings.TrimSpace(line)

        // Extrair portas abertas
        if strings.Contains(line, "/tcp") && strings.Contains(line, "open") {
            fields := strings.Fields(line)
            if len(fields) >= 4 {
                portStr := strings.Split(fields[0], "/")[0]
                port, _ := strconv.Atoi(portStr)
                service := fields[2]
                version := strings.Join(fields[3:], " ")

                result.Ports = append(result.Ports, models.PortService{
                    Port:     port,
                    Protocol: "tcp",
                    Service:  service,
                    Version:  version,
                })
            }
        }

        // Extrair MAC
        if strings.HasPrefix(line, "MAC Address:") {
            parts := strings.SplitN(line, ":", 2)
            if len(parts) == 2 {
                result.MAC = strings.TrimSpace(parts[1])
            }
        }

        // Extrair OS
        if strings.HasPrefix(line, "OS details:") {
            result.OS = strings.TrimSpace(strings.TrimPrefix(line, "OS details:"))
        } else if strings.HasPrefix(line, "Running:") && result.OS == "" {
            result.OS = strings.TrimSpace(strings.TrimPrefix(line, "Running:"))
        }
    }

    return result
}


func RunNmapMultiFast(hosts map[string][]int) map[string]models.HostResult {
    if len(hosts) == 0 {
        return nil
    }

    var allIPs []string
    portSet := make(map[int]struct{})
    for ip, ports := range hosts {
        allIPs = append(allIPs, ip)
        for _, p := range ports {
            portSet[p] = struct{}{}
        }
    }

    var uniquePorts []string
    for p := range portSet {
        uniquePorts = append(uniquePorts, strconv.Itoa(p))
    }

    portsStr := strings.Join(uniquePorts, ",")

    args := append([]string{
        "-T4", "--max-retries", "1", "--host-timeout", "30s",
        "-Pn", "-sV", "-O", "-p", portsStr,
    }, allIPs...)

    log.Printf("[DEBUG] Executando NmapMultiFast: nmap %s", strings.Join(args, " "))
    out, err := exec.Command("nmap", args...).Output()
    if err != nil {
        log.Printf("[ERROR] NmapMultiFast falhou: %v", err)
        return nil
    }

    return parseNmapMultiOutput(string(out))
}

func parseNmapMultiOutput(output string) map[string]models.HostResult {
    results := make(map[string]models.HostResult)
    blocks := strings.Split(output, "Nmap scan report for ")

    for _, block := range blocks[1:] {
        lines := strings.Split(block, "\n")
        hostLine := strings.Fields(lines[0])
        if len(hostLine) == 0 {
            continue
        }

        ip := hostLine[len(hostLine)-1]
        var mac, os string
        var ports []models.PortService

        for _, line := range lines {
            if strings.Contains(line, "/tcp") && strings.Contains(line, "open") {
                fields := strings.Fields(line)
                if len(fields) >= 4 {
                    portStr := strings.Split(fields[0], "/")[0]
                    port, _ := strconv.Atoi(portStr)
                    service := fields[2]
                    version := strings.Join(fields[3:], " ")

                    ports = append(ports, models.PortService{
                        Port:     port,
                        Protocol: "tcp",
                        Service:  service,
                        Version:  version,
                    })
                }
            }
            if strings.HasPrefix(line, "MAC Address:") {
                mac = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
            }
            if strings.HasPrefix(line, "OS details:") {
                os = strings.TrimSpace(strings.TrimPrefix(line, "OS details:"))
            } else if strings.HasPrefix(line, "Running:") && os == "" {
                os = strings.TrimSpace(strings.TrimPrefix(line, "Running:"))
            }
        }

        results[ip] = models.HostResult{
            Host:  ip,
            MAC:   mac,
            OS:    os,
            Ports: ports,
        }
    }

    return results
}
