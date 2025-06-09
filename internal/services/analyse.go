package services

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
)

func AnalyzeWithN8N(hostData interface{}) map[string]interface{} {
	webhookURL := "https://n8n.srv794951.hstgr.cloud/webhook-test/5d00c979-3cbc-402c-8be6-6dd92036e6a6"

	payload, _ := json.Marshal(hostData)
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		log.Printf("[ERROR] Falha ao enviar dados ao n8n: %v", err)
		return nil
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("[ERROR] Falha ao decodificar resposta do n8n: %v", err)
		return nil
	}

	return result
}
