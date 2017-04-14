package onelogin

import (
	"context"
)

// UserService handles communications with the authentication related methods on OneLogin.
type UserService service

// User represents a OneLogin user.
type User struct {
	ActivatedAt          string            `json:"activated_at"`
	CreatedAt            string            `json:"created_at"`
	Email                string            `json:"email"`
	Username             string            `json:"username"`
	FirstName            string            `json:"firstname"`
	GroupID              int               `json:"group_id"`
	ID                   int               `json:"id"`
	InvalidLoginAttempts int               `json:"invalid_login_attempts"`
	InvitationSentAt     string            `json:"invitation_sent_at"`
	LastLogin            string            `json:"last_login"`
	LastName             string            `json:"lastname"`
	LockedUntil          string            `json:"locked_until"`
	Notes                string            `json:"notes"`
	OpenidName           string            `json:"openid_name"`
	LocaleCode           string            `json:"locale_code"`
	PasswordChangedAt    string            `json:"password_changed_at"`
	Phone                string            `json:"phone"`
	Status               int               `json:"status"`
	UpdatedAt            string            `json:"updated_at"`
	DistinguishedName    string            `json:"distinguished_name"`
	ExternalID           int               `json:"external_id"`
	DirectoryID          int               `json:"directory_id"`
	MemberOf             []string          `json:"member_of"`
	SamAccountName       string            `json:"samaccountname"`
	UserPrincipalName    string            `json:"userprincipalname"`
	ManagerAdID          int               `json:"manager_ad_id"`
	RoleIDs              []int             `json:"role_id"`
	CustomAttributes     map[string]string `json:"custom_attributes"`
}

type getUserQuery struct {
	AfterCursor string `url:"after_cursor,omitempty"`
}

// GetUsers returns all the OneLogin users.
func (s *UserService) GetUsers(ctx context.Context) ([]User, error) {
	u := "/api/1/users"

	var users []User
	var afterCursor string

	for {
		uu, err := addOptions(u, &getUserQuery{AfterCursor: afterCursor})
		if err != nil {
			return nil, err
		}

		req, err := s.client.NewRequest("GET", uu, nil)
		if err != nil {
			return nil, err
		}

		if err := s.client.AddAuthorization(ctx, req); err != nil {
			return nil, err
		}

		var us []User
		resp, err := s.client.Do(ctx, req, &us)
		if err != nil {
			return nil, err
		}
		users = append(users, us...)
		if resp.PaginationAfterCursor == nil {
			break
		}

		afterCursor = *resp.PaginationAfterCursor
	}

	return users, nil
}
