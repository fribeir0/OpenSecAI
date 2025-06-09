package services

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "net/url"
    "strings"
    "sync"
    "go-recon-ai-modular/internal/models"
)

var cveCache = make(map[string][]models.CVEInfo)
var cveMu sync.Mutex

func EnrichWithCVEs(service, version string) []models.CVEInfo {
    if service == "" || version == "" {
        return nil
    }

    key := fmt.Sprintf("%s %s", service, version)

    // Verifica o cache antes
    cveMu.Lock()
    if cached, found := cveCache[key]; found {
        cveMu.Unlock()
        return cached
    }
    cveMu.Unlock()

    query := url.QueryEscape(key)
    apiURL := fmt.Sprintf("https://vulners.com/api/v3/search/lucene/?query=%s", query)

    resp, err := http.Get(apiURL)
    if err != nil {
        log.Printf("[ERROR] Erro ao consultar Vulners para %s: %v", key, err)
        return nil
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        log.Printf("[WARN] Vulners retornou status %d para %s", resp.StatusCode, key)
        return nil
    }

    var apiResp struct {
        Data struct {
            Documents []struct {
                ID     string  `json:"id"`
                CVSS   float64 `json:"cvss"`
                Title  string  `json:"title"`
                Source string  `json:"source"`
                URL    string  `json:"href"`
            } `json:"documents"`
        } `json:"data"`
    }

    if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
        log.Printf("[ERROR] Erro ao decodificar resposta da Vulners: %v", err)
        return nil
    }

    var cves []models.CVEInfo
    for _, doc := range apiResp.Data.Documents {
        if strings.HasPrefix(doc.ID, "CVE-") {
            cves = append(cves, models.CVEInfo{
                ID:   doc.ID,
                CVSS: doc.CVSS,
                Desc: doc.Title,
                Link: doc.URL,
            })
        }
    }

    // Salva no cache
    cveMu.Lock()
    cveCache[key] = cves
    cveMu.Unlock()

    return cves
}
