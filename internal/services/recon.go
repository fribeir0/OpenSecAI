package services

import (
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"encoding/json"
	"strings"
	"net/http"
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

func enrichVulns(vs []models.Vulnerability) {
	for i := range vs {
		id := vs[i].ID
		// busca na API pública
		url := "https://cve.circl.lu/api/cve/" + id
		resp, err := http.Get(url)
		if err != nil {
			log.Printf("[WARN] erro ao buscar %s: %v", id, err)
			continue
		}
		defer resp.Body.Close()

		var d models.CveDetail
		if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
			log.Printf("[WARN] decode falhou para %s: %v", id, err)
			continue
		}

		vs[i].Link = fmt.Sprintf("https://cve.circl.lu/cve/%s", id)
		vs[i].Description = d.Summary
		vs[i].CVSS = d.Cvss
	}
}

func RunNmapVulners(target string, ports []int) models.HostResult {
	var result models.HostResult
	result.Host = target

	if len(ports) == 0 {
		return result
	}

	portsStr := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(ports)), ","), "[]")
	args := []string{
		"-T4", "--max-retries", "1", "--host-timeout", "30s",
		"-p", portsStr,
		"-Pn", "--script", "vulners",
		target,
	}

	out, err := exec.Command("nmap", args...).Output()
	if err != nil {
		log.Printf("[ERROR] NmapVulners falhou para %s: %v", target, err)
		return result
	}

	// extrai só os IDs
	for _, line := range strings.Split(string(out), "\n") {
		if parts := strings.SplitN(line, "Vulners:", 2); len(parts) == 2 {
			for _, id := range strings.Split(parts[1], ",") {
				id = strings.TrimSpace(id)
				if id != "" {
					result.Vulnerabilities = append(result.Vulnerabilities, models.Vulnerability{
						ID:     id,
						Source: "vulners",
					})
				}
			}
		}
	}

	// agora enrich
	enrichVulns(result.Vulnerabilities)
	return result
}

func RunNmapMultiFast(hosts map[string][]int) map[string]models.HostResult {
    results := make(map[string]models.HostResult)

    if len(hosts) == 0 {
        return results
    }

    // coleta IPs e porta única
    var allIPs []string
    portSet := make(map[int]struct{})
    for ip, ports := range hosts {
        allIPs = append(allIPs, ip)
        for _, p := range ports {
            portSet[p] = struct{}{}
        }
    }

    // monta "22,80,443"
    var uniquePorts []string
    for p := range portSet {
        uniquePorts = append(uniquePorts, strconv.Itoa(p))
    }
    portsStr := strings.Join(uniquePorts, ",")

    // args: somente vulners
    args := []string{
        "-T4", "--max-retries", "1", "--host-timeout", "30s",
        "-Pn", "-p", portsStr,
        "--script", "vulners",
    }
    args = append(args, allIPs...)

    log.Printf("[DEBUG] nmap %s", strings.Join(args, " "))
    out, err := exec.Command("nmap", args...).Output()
    if err != nil {
        log.Printf("[ERROR] NmapMultiFast falhou: %v", err)
        return results
    }

    // parse bloque por host
    blocks := strings.Split(string(out), "Nmap scan report for ")
    for _, block := range blocks[1:] {
        lines := strings.Split(block, "\n")
        header := strings.Fields(lines[0])
        if len(header) == 0 {
            continue
        }
        ip := header[len(header)-1]
        hr := models.HostResult{ Host: ip }

        // extrai IDs CVE e adiciona ao slice
        for _, line := range lines {
            line = strings.TrimSpace(line)
            if parts := strings.SplitN(line, "Vulners:", 2); len(parts) == 2 {
                for _, id := range strings.Split(parts[1], ",") {
                    id = strings.TrimSpace(id)
                    if id != "" {
                        hr.Vulnerabilities = append(hr.Vulnerabilities, models.Vulnerability{
                            ID:     id,
                            Source: "vulners",
                        })
                    }
                }
            }
        }

        enrichVulns(hr.Vulnerabilities)
        results[ip] = hr
    }

    return results
}