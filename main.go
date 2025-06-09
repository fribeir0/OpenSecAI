package main

import (
    "github.com/gin-gonic/gin"
    "go-recon-ai-modular/internal/handlers"
)

func main() {
    r := gin.Default()
    r.POST("/recon", handlers.ReconHandler)
    r.Run(":8080")
}
