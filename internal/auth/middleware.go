package auth

import (
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

func RequireAuth(secret []byte) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authHeader := c.Request().Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				return echo.NewHTTPError(http.StatusUnauthorized, "Missing or invalid token")
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			claims := &JWTClaims{}

			token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
				return secret, nil
			})

			if err != nil || !token.Valid {
				return echo.NewHTTPError(http.StatusUnauthorized, "Token tidak valid atau sudah kedaluwarsa")
			}

			c.Set("user", claims)

			if claims.MustChangePassword && c.Path() != "/api/auth/first-login-change" {
				return echo.NewHTTPError(http.StatusForbidden, "Wajib mengganti password terlebih dahulu")
			}

			return next(c)
		}
	}
}

func RequireRole(roles ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user := c.Get("user").(*JWTClaims)
			for _, role := range roles {
				if user.Role == role {
					return next(c)
				}
			}
			return echo.NewHTTPError(http.StatusForbidden, "Akses ditolak")
		}
	}
}
