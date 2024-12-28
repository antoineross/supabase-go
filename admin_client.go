package supabase

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/supabase-community/auth-go/types"
)

func (c *Client) AdminGetUser(userID string) (*types.AdminGetUserResponse, error) {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID format: %w", err)
	}

	return c.Auth.AdminGetUser(types.AdminGetUserRequest{
		UserID: userUUID,
	})
}

func (c *Client) AdminListUsers() (*types.AdminListUsersResponse, error) {
	return c.Auth.AdminListUsers()
}

func (c *Client) AdminCreateUser(req types.AdminCreateUserRequest) (*types.AdminCreateUserResponse, error) {
	return c.Auth.AdminCreateUser(req)
}

func (c *Client) AdminUpdateUser(userID string, updates types.AdminUpdateUserRequest) (*types.AdminUpdateUserResponse, error) {
	userIDUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID format: %w", err)
	}
	updates.UserID = userIDUUID
	return c.Auth.AdminUpdateUser(updates)
}

func (c *Client) AdminDeleteUser(userID string) error {
	userIDUUID, err := uuid.Parse(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID format: %w", err)
	}
	return c.Auth.AdminDeleteUser(types.AdminDeleteUserRequest{
		UserID: userIDUUID,
	})
}
