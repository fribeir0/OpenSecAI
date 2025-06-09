package services

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

func AnalyzeWithN8N(hostData interface{}) map[string]interface{} {
	webhookURL := "https://n8n.srv794951.hstgr.cloud/webhook/5d00c979-3cbc-402c-8be6-6dd92036e6a6"

	payload, _ := json.Marshal(hostData)

	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		log.Printf("[ERROR] Falha ao enviar dados ao n8n: %v", err)
		return nil
	}
	defer resp.Body.Close()

	var resultArr []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&resultArr); err == nil && len(resultArr) > 0 {
		return resultArr[0]
	}

	var wrapper []struct {
		Output string `json:"output"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err == nil && len(wrapper) > 0 {
		clean := strings.TrimSpace(wrapper[0].Output)
		clean = strings.TrimPrefix(clean, "```json")
		clean = strings.TrimSuffix(clean, "```")
		clean = strings.TrimSpace(clean)

		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(clean), &parsed); err == nil {
			return parsed
		}
		log.Printf("[ERROR] Falha ao parsear JSON limpo da string: %v", err)
		log.Printf("[DEBUG] Conteúdo retornado (limpo): %s", clean)
	}

	log.Printf("[ERROR] Falha ao decodificar resposta do n8n completamente")
	return nil
}
