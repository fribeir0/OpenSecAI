package main

import (
    "github.com/gin-gonic/gin"
    "go-recon-ai-modular/internal/handlers"
    "log"
    "os"
)

func main() {
    r := gin.Default()

    r.GET("/", func(c *gin.Context) {
        c.File("./web/index.html")
    })

    r.POST("/recon", handlers.ReconHandler)

    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }
    log.Printf("Iniciando servidor na porta %s...", port)

    r.Run(":" + port)
}
