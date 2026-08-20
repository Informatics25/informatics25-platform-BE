package dashboard

import (
	"context"
	"fmt"

	"github.com/Informatics25/informatics25-platform-BE/internal/auth"
	"github.com/Informatics25/informatics25-platform-BE/internal/iam"
	"github.com/Informatics25/informatics25-platform-BE/pkg/database"
)

type Service struct {
	q *database.Queries
}

func NewService(q *database.Queries) *Service {
	return &Service{q: q}
}

func (s *Service) GetDashboardSummary(ctx context.Context, claims *auth.JWTClaims) (*DashboardSummaryResponse, error) {
	userProfile, err := s.q.GetProfileByAccountID(ctx, claims.AccountID)
	fullName := claims.NIM
	if err == nil && userProfile.FullName != "" {
		fullName = userProfile.FullName
	}

	schedulesDB, err := s.q.GetTodaySchedules(ctx)
	if err != nil {
		schedulesDB = []database.Schedule{}
	}

	var schedules []Schedule
	for _, sch := range schedulesDB {
		schedules = append(schedules, Schedule{
			Time:     fmt.Sprintf("%s - %s", sch.TimeStart.Format("15:04"), sch.TimeEnd.Format("15:04")),
			Activity: sch.Activity,
			Location: sch.Location,
		})
	}

	announcementsDB, err := s.q.GetLatestAnnouncements(ctx)
	if err != nil {
		announcementsDB = []database.Announcement{}
	}

	var announcements []Information
	for _, ann := range announcementsDB {
		announcements = append(announcements, Information{
			Title:   ann.Title,
			Content: ann.Content,
			Date:    ann.CreatedAt.Time.Format("02 Jan 2006"),
		})
	}

	quickLinks := s.generateNavigationByRole(claims.Role)

	return &DashboardSummaryResponse{
		UserInfo: UserInfo{
			FullName: fullName,
			Role:     claims.Role,
			Status:   "ACTIVE",
		},
		TodaySchedule: schedules,
		ImportantInfo: announcements,
		QuickLinks:    quickLinks,
	}, nil
}

func (s *Service) generateNavigationByRole(role string) []Navigation {
	navs := []Navigation{
		{Label: "Profil Saya", URL: "/api/users/profile/me", Icon: "user"},
	}

	switch role {
	case iam.RoleMahasiswa:
		navs = append(navs,
			Navigation{Label: "Unggah Resource", URL: "/api/resources/upload", Icon: "upload"},
			Navigation{Label: "Lihat Jadwal", URL: "/api/schedules", Icon: "calendar"},
		)
	case iam.RoleAdministrator, iam.RoleSuperadmin:
		navs = append(navs,
			Navigation{Label: "Manajemen Mahasiswa", URL: "/api/admin/users/invite", Icon: "user-plus"},
			Navigation{Label: "Kelola Jadwal", URL: "/api/schedules/manage", Icon: "calendar-edit"},
		)
		if role == iam.RoleSuperadmin {
			navs = append(navs,
				Navigation{Label: "Tambah Admin", URL: "/api/superadmin/users/admin", Icon: "shield"},
			)
		}
	}

	return navs
}
