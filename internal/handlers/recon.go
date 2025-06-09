package handlers

import (
    "log"
    "net"
    "net/http"
    "strings"

    "github.com/gin-gonic/gin"
    "go-recon-ai-modular/internal/models"
    "go-recon-ai-modular/internal/services"
)

func ReconHandler(c *gin.Context) {
    var req models.ReconRequest
    if err := c.BindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "JSON inválido: " + err.Error()})
        return
    }

    target := req.Target
    portas := req.Ports
    var finalResults []models.HostResult

    if net.ParseIP(target) != nil || strings.Contains(target, "/") {
        log.Println("[INFO] IP/CIDR detected:", target)

        openPortsMap := services.RunNaabuCIDR(target, portas)
        nmapResults := services.RunNmapMulti(openPortsMap)

        for ip, ports := range nmapResults {
            finalResults = append(finalResults, models.HostResult{
                Host:  ip,
                Ports: ports,
            })
        }
    } else {
        log.Println("[INFO] Domain detected:", target)
        subs := services.RunSubfinder(target)
        log.Printf("[INFO] %d subdomínios encontrados para %s", len(subs), target)

        for _, sub := range subs {
            ips, err := net.LookupHost(sub)
            if err != nil || len(ips) == 0 {
                log.Printf("[INFO] Ignorando %s: não resolve", sub)
                continue
            }
            openPorts := services.RunNaabu(sub, portas)
            if len(openPorts) == 0 {
                continue
            }
            log.Printf("[INFO] Portas abertas em %s: %v", sub, openPorts)
            details := services.RunNmap(sub, openPorts)
            finalResults = append(finalResults, models.HostResult{
                Host:  sub,
                Ports: details,
            })
        }
    }

    if len(finalResults) == 0 {
        c.JSON(http.StatusOK, []models.HostResult{})
    } else {
        c.JSON(http.StatusOK, finalResults)
    }
}
