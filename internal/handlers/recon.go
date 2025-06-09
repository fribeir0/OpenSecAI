package handlers

import (
    "log"
    "net"
    "net/http"
    "strings"
    "sync"

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
        if len(openPortsMap) > 0 {
            nmapResults := services.RunNmapMultiFast(openPortsMap)
            for _,result := range nmapResults {
                finalResults = append(finalResults, result)
            }
        }
    } else {
        log.Println("[INFO] Domain detected:", target)
        subs := services.RunSubfinder(target)
        log.Printf("[INFO] %d subdomínios encontrados para %s", len(subs), target)

        var wg sync.WaitGroup
        var mu sync.Mutex

        for _, sub := range subs {
            sub := sub // evitar race condition
            wg.Add(1)

            go func() {
                defer wg.Done()

                ips, err := net.LookupHost(sub)
                if err != nil || len(ips) == 0 {
                    log.Printf("[INFO] Ignorando %s: não resolve", sub)
                    return
                }

                openPorts := services.RunNaabu(sub, portas)
                if len(openPorts) == 0 {
                    return
                }

                result := services.RunNmapFast(sub, openPorts)

                mu.Lock()
                finalResults = append(finalResults, models.HostResult{
                    Host:  sub,
                    MAC:   result.MAC,
                    OS:    result.OS,
                    Ports: result.Ports,
                })
                mu.Unlock()
            }()
        }

        wg.Wait()
    }

    if len(finalResults) == 0 {
        c.JSON(http.StatusOK, []models.HostResult{})
    } else {
        c.JSON(http.StatusOK, finalResults)
    }
}
