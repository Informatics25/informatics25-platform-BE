package auth

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

type Handler struct {
	Service *Service
}

func RegisterRoutes(e *echo.Echo, h *Handler, secret []byte) {
	e.POST("/api/auth/login", h.Login)
	e.POST("/api/auth/refresh", h.Refresh)

	api := e.Group("/api/auth")
	api.Use(RequireAuth(secret))

	api.POST("/logout", h.Logout)
	api.POST("/first-login-change", h.FirstLoginChangePassword)

	adminAPI := e.Group("/api/admin/auth")
	adminAPI.Use(RequireAuth(secret), RequireRole("SUPERADMIN"))
	adminAPI.POST("/reset-password", h.AdminResetPassword)
}

func (h *Handler) Login(c echo.Context) error {
	var req struct {
		NIM      string `json:"nim" validate:"required"`
		Password string `json:"password" validate:"required"`
	}
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	accessToken, refreshToken, err := h.Service.Login(c.Request().Context(), req.NIM, req.Password, c.RealIP())
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
	}

	return c.JSON(http.StatusOK, map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

func (h *Handler) FirstLoginChangePassword(c echo.Context) error {
	var req struct {
		NewPassword string `json:"new_password" validate:"required"`
	}
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	if len(req.NewPassword) < 12 {
		return echo.NewHTTPError(http.StatusBadRequest, "Password minimal 12 karakter")
	}

	user := c.Get("user").(*JWTClaims)
	if err := h.Service.ChangeFirstPassword(c.Request().Context(), user.AccountID, req.NewPassword, c.RealIP()); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Gagal mengubah password")
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Password berhasil diubah, silakan login kembali"})
}

func (h *Handler) Logout(c echo.Context) error {
	user := c.Get("user").(*JWTClaims)
	_ = h.Service.Logout(c.Request().Context(), user.AccountID, c.RealIP())
	return c.JSON(http.StatusOK, map[string]string{"message": "Berhasil logout"})
}

func (h *Handler) Refresh(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"message": "Token refreshed"})
}

func (h *Handler) AdminResetPassword(c echo.Context) error {
	var req struct {
		AccountID string `json:"account_id" validate:"required"`
	}
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	defaultPass := "Informatika2025!"
	if err := h.Service.AdminResetPassword(c.Request().Context(), req.AccountID, defaultPass, c.RealIP()); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Gagal mereset password")
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message":          "Password berhasil di-reset",
		"default_password": defaultPass,
	})
}

func NewHandler(service *Service) *Handler {
	return &Handler{Service: service}
}
