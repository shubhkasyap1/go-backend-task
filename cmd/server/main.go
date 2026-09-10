package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/shubhkasyap1/go-backend-task/internal/auth"
	"github.com/shubhkasyap1/go-backend-task/internal/config"
	"github.com/shubhkasyap1/go-backend-task/internal/database"
	"github.com/shubhkasyap1/go-backend-task/internal/middleware"
	"github.com/shubhkasyap1/go-backend-task/internal/user"
)

func main() {
	cfg := config.Load()

	db, err := database.Connect(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	defer cancel()

	if err := database.RunMigrations(ctx, db); err != nil {
		log.Fatal(err)
	}

	userRepo := user.NewRepository(db)

	sessionRepo := auth.NewSessionRepository(db)

	authService := auth.NewService(
		userRepo,
		sessionRepo,
	)

	authHandler := auth.NewHandler(
		authService,
		sessionRepo,
	)

	router := gin.Default()

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":   "ok",
			"message":  "server is healthy",
			"database": "connected",
		})
	})

	authRoutes := router.Group("/api/v1/auth")
	{
		authRoutes.POST("/register", authHandler.Register)
		authRoutes.POST("/login", authHandler.Login)
		authRoutes.POST("/login/2fa", authHandler.LoginMFA)
	}

	protectedRoutes := router.Group("/api/v1/auth")

	protectedRoutes.Use(
		middleware.Auth(
			sessionRepo,
			userRepo,
		),
	)

	{
		protectedRoutes.GET("/me", authHandler.Me)
		protectedRoutes.POST("/logout", authHandler.Logout)

		protectedRoutes.POST("/enable-2fa", authHandler.EnableMFA)
		protectedRoutes.POST("/disable-2fa", authHandler.DisableMFA)
		protectedRoutes.POST("/verify-2fa", authHandler.VerifyMFA)
	}

	log.Printf("Server running on :%s", cfg.AppPort)

	if err := router.Run(":" + cfg.AppPort); err != nil {
		log.Fatal(err)
	}
}
