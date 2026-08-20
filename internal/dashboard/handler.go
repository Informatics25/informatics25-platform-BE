package dashboard

import (
	"net/http"

	"github.com/Informatics25/informatics25-platform-BE/internal/auth"
	"github.com/labstack/echo/v4"
)

type DashboardSummaryResponse struct {
	UserInfo      UserInfo      `json:"user_info"`
	TodaySchedule []Schedule    `json:"today_schedule"`
	ImportantInfo []Information `json:"important_info"`
	QuickLinks    []Navigation  `json:"quick_links"`
}

type UserInfo struct {
	FullName string `json:"full_name"`
	Role     string `json:"role"`
	Status   string `json:"status"`
}

type Schedule struct {
	Time     string `json:"time"`
	Activity string `json:"activity"`
	Location string `json:"location"`
}

type Information struct {
	Title   string `json:"title"`
	Content string `json:"content"`
	Date    string `json:"date"`
}

type Navigation struct {
	Label string `json:"label"`
	URL   string `json:"url"`
	Icon  string `json:"icon"`
}

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func RegisterDashboardRoutes(e *echo.Echo, h *Handler, secret []byte) {
	api := e.Group("/api/dashboard")
	api.Use(auth.RequireAuth(secret))

	api.GET("/summary", h.GetDashboardSummary)
}

func (h *Handler) GetDashboardSummary(c echo.Context) error {
	userClaims, ok := c.Get("user").(*auth.JWTClaims)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "Sesi tidak valid")
	}

	summary, err := h.service.GetDashboardSummary(c.Request().Context(), userClaims)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Gagal mengambil data dashboard")
	}

	return c.JSON(http.StatusOK, summary)
}
