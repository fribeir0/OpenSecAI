package utils

import (
    "log"
    "os"

    "github.com/go-resty/resty/v2"
    "go-recon-ai-modular/internal/models"
)

// SendToN8n envia o resultado do reconhecimento para um webhook n8n
func SendToN8n(result models.HostResult) {
    url := os.Getenv("N8N_ENDPOINT")
    if url == "" {
        log.Println("N8N_ENDPOINT não definido")
        return
    }

    client := resty.New()
    resp, err := client.R().
        SetHeader("Content-Type", "application/json").
        SetBody(result).
        Post(url)

    if err != nil {
        log.Println("Erro ao enviar para n8n:", err)
        return
    }

    log.Printf("Resposta do n8n: %d", resp.StatusCode())
}
