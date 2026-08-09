package iam

import (
	"net/http"

	"github.com/Informatics25/informatics25-platform-BE/internal/auth"
	"github.com/labstack/echo/v4"
)

type Handler struct {
	Service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{
		Service: service,
	}
}

func RegisterUserRoutes(e *echo.Echo, h *Handler, secret []byte) {
	api := e.Group("/api/users")
	api.Use(auth.RequireAuth(secret))

	api.GET("/profile/me", h.GetMyProfile)
	api.PUT("/profile/me", h.UpdateMyProfile)
	api.GET("/:id/profile", h.GetUserProfile)

	adminAPI := e.Group("/api/admin/users")
	adminAPI.Use(auth.RequireAuth(secret), RequirePermission(h.Service, PermManageUserBasic))
	adminAPI.POST("/invite", h.InviteMahasiswa)
	adminAPI.PUT("/:id/suspend", h.SuspendMahasiswa)

	superAPI := e.Group("/api/superadmin/users")
	superAPI.Use(auth.RequireAuth(secret), RequirePermission(h.Service, PermManageUserFull))
	superAPI.POST("/admin", h.CreateAdministrator)
	superAPI.POST("/:id/reset-password", h.ForceResetPassword)
}

func (h *Handler) GetMyProfile(c echo.Context) error {
	user := c.Get("user").(*auth.JWTClaims)
	profile, err := h.Service.GetProfileByID(c.Request().Context(), user.AccountID)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, err.Error())
	}
	return c.JSON(http.StatusOK, profile)
}

func (h *Handler) UpdateMyProfile(c echo.Context) error {
	user := c.Get("user").(*auth.JWTClaims)
	var req UpdateProfileRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Format request tidak valid")
	}

	err := h.Service.UpdateProfile(c.Request().Context(), user.AccountID, req)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Gagal memperbarui profil")
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Profil berhasil diperbarui"})
}

func (h *Handler) GetUserProfile(c echo.Context) error {
	targetID := c.Param("id")
	requester := c.Get("user").(*auth.JWTClaims)

	profile, err := h.Service.GetProfileByID(c.Request().Context(), targetID)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "Profil tidak ditemukan")
	}

	if requester.Role == RoleMahasiswa && requester.AccountID != targetID {
		if !profile.IsPublic {
			return echo.NewHTTPError(http.StatusForbidden, "Profil ini bersifat privat")
		}
		profile.Nim = maskNIM(profile.Nim)
	}

	return c.JSON(http.StatusOK, profile)
}

func (h *Handler) InviteMahasiswa(c echo.Context) error {
	var req struct {
		NIM      string `json:"nim" validate:"required"`
		FullName string `json:"full_name" validate:"required"`
	}
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Input tidak valid")
	}

	requester := c.Get("user").(*auth.JWTClaims)

	account, tempPassword, err := h.Service.CreateMahasiswaAccount(c.Request().Context(), req.NIM, req.FullName)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	// Gunakan fungsi asli untuk mencatat log
	h.Service.LogAudit(c.Request().Context(), requester.AccountID, "CREATE_USER_ACCOUNT", "Created ID: "+account.ID.String(), c.RealIP())

	return c.JSON(http.StatusCreated, map[string]interface{}{
		"account":       account,
		"temp_password": tempPassword,
	})
}

func (h *Handler) SuspendMahasiswa(c echo.Context) error {
	targetID := c.Param("id")
	requester := c.Get("user").(*auth.JWTClaims)

	err := h.Service.SuspendMahasiswa(c.Request().Context(), targetID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Gagal menonaktifkan akun")
	}

	h.Service.LogAudit(c.Request().Context(), requester.AccountID, "SUSPEND_USER_ACCOUNT", "Suspended ID: "+targetID, c.RealIP())

	return c.JSON(http.StatusOK, map[string]string{"message": "Akun berhasil dinonaktifkan"})
}

func (h *Handler) CreateAdministrator(c echo.Context) error {
	var req struct {
		NIM      string `json:"nim" validate:"required"`
		FullName string `json:"full_name" validate:"required"`
	}
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Input tidak valid")
	}

	requester := c.Get("user").(*auth.JWTClaims)

	account, tempPassword, err := h.Service.CreateAdministrator(c.Request().Context(), req.NIM, req.FullName)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	h.Service.LogAudit(c.Request().Context(), requester.AccountID, "CREATE_ADMINISTRATOR", "Created Admin ID: "+account.ID.String(), c.RealIP())

	return c.JSON(http.StatusCreated, map[string]interface{}{
		"account":       account,
		"temp_password": tempPassword,
	})
}

func (h *Handler) ForceResetPassword(c echo.Context) error {
	targetID := c.Param("id")
	requester := c.Get("user").(*auth.JWTClaims)

	tempPassword, err := h.Service.ForceResetPassword(c.Request().Context(), targetID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Gagal mereset password")
	}

	h.Service.LogAudit(c.Request().Context(), requester.AccountID, "FORCE_RESET_PASSWORD", "Reset password for ID: "+targetID, c.RealIP())

	return c.JSON(http.StatusOK, map[string]string{
		"message":       "Password berhasil direset",
		"temp_password": tempPassword,
	})
}

func maskNIM(nim string) string {
	if len(nim) <= 4 {
		return nim
	}
	return nim[:len(nim)-4] + "XXXX"
}
