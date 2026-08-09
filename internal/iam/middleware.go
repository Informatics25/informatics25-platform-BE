package iam

import (
	"net/http"

	"github.com/Informatics25/informatics25-platform-BE/internal/auth"
	"github.com/labstack/echo/v4"
)

func RequirePermission(s *Service, requiredPerm string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user, ok := c.Get("user").(*auth.JWTClaims)
			if !ok {
				return echo.NewHTTPError(http.StatusUnauthorized, "Sesi tidak valid")
			}

			if !HasPermission(user.Role, requiredPerm) {
				s.LogAudit(c.Request().Context(), user.AccountID, "UNAUTHORIZED_ACCESS_ATTEMPT", "Mencoba mengakses: "+requiredPerm, c.RealIP())
				return echo.NewHTTPError(http.StatusForbidden, "Akses ditolak: Privilege tidak mencukupi")
			}

			if (user.Role == RoleAdministrator || user.Role == RoleSuperadmin) && !user.TOTPVerified {
				return echo.NewHTTPError(http.StatusForbidden, "Otorisasi 2FA/TOTP diwajibkan")
			}

			return next(c)
		}
	}
}
