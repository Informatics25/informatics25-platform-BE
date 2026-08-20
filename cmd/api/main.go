package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/Informatics25/informatics25-platform-BE/internal/auth"
	"github.com/Informatics25/informatics25-platform-BE/internal/dashboard"
	"github.com/Informatics25/informatics25-platform-BE/internal/iam"
	"github.com/Informatics25/informatics25-platform-BE/pkg/database"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:postgres@localhost:5432/informatics25?sslmode=disable"
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Gagal membuka koneksi database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("Gagal terhubung ke database: %v", err)
	}

	queries := database.New(db)

	jwtSecretStr := os.Getenv("JWT_SECRET")
	if jwtSecretStr == "" {
		jwtSecretStr = "super-secret-key-change-me"
	}
	jwtSecret := []byte(jwtSecretStr)

	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())
	e.Use(middleware.Secure())

	authService := auth.NewService(queries, jwtSecret)
	authHandler := auth.NewHandler(authService)

	auth.RegisterRoutes(e, authHandler, jwtSecret)

	iamService := iam.NewService(queries)
	iamHandler := iam.NewHandler(iamService)
	iam.RegisterUserRoutes(e, iamHandler, jwtSecret)

	dashboardService := dashboard.NewService(queries)
	dashboardHandler := dashboard.NewHandler(dashboardService)
	dashboard.RegisterDashboardRoutes(e, dashboardHandler, jwtSecret)

	e.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "healthy"})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting server on port %s", port)
	e.Logger.Fatal(e.Start(":" + port))
}
