// bakcend/internal/iam/rbac.go
package iam

const (
	RoleGuest         = "GUEST"
	RoleMahasiswa     = "MAHASISWA"
	RoleAdministrator = "ADMINISTRATOR"
	RoleSuperadmin    = "SUPERADMIN"
)

const (
	PermViewInternalInfo = "view:internal_info"
	PermManageInfo       = "manage:info"
	PermManageSchedule   = "manage:schedule"
	PermUploadResource   = "upload:resource"
	PermApproveResource  = "approve:resource"
	PermSendNotification = "send:notification"
	PermManageUserBasic  = "manage:user_basic"
	PermManageUserFull   = "manage:user_full"
	PermResetPassword    = "manage:reset_password"
	PermManageConfig     = "manage:config"
)

var RolePermissions = map[string][]string{
	RoleMahasiswa: {
		PermViewInternalInfo,
		PermUploadResource,
	},
	RoleAdministrator: {
		PermViewInternalInfo,
		PermUploadResource,
		PermManageInfo,
		PermManageSchedule,
		PermApproveResource,
		PermSendNotification,
		PermManageUserBasic,
	},
	RoleSuperadmin: {
		PermViewInternalInfo,
		PermUploadResource,
		PermManageInfo,
		PermManageSchedule,
		PermApproveResource,
		PermSendNotification,
		PermManageUserBasic,
		PermManageUserFull,
		PermResetPassword,
		PermManageConfig,
	},
}

func HasPermission(role string, requiredPerm string) bool {
	perms, exists := RolePermissions[role]
	if !exists {
		return false
	}
	for _, p := range perms {
		if p == requiredPerm {
			return true
		}
	}
	return false
}
