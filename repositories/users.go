package repositories

import (
	"fmt"
	"github.com/go-ldap/ldap"
	"tunnel-provisioner-service/config"
	"tunnel-provisioner-service/models"
)

const (
	PageSize = 128
)

type UsersRepository interface {
	GetUsers() (map[string]models.User, error)
	Authenticate(username, password string) error
}

type LDAPUsersRepository struct {
	config config.LDAPConfiguration
}

func NewLDAPUsersRepository(ldapConfiguration config.LDAPConfiguration) *LDAPUsersRepository {
	ldapProviderImpl := &LDAPUsersRepository{config: ldapConfiguration}
	return ldapProviderImpl
}

func (l *LDAPUsersRepository) GetUsers() (map[string]models.User, error) {

	connection, err := ldap.DialURL(l.config.LdapURL)
	if err != nil {
		return nil, err
	}

	defer connection.Close()

	err = l.bind(connection)
	if err != nil {
		return nil, err
	}

	return l.retrieveUserSet(connection)
}

func (l *LDAPUsersRepository) Authenticate(username, password string) error {

	connection, err := ldap.DialURL(l.config.LdapURL)
	if err != nil {
		return err
	}

	defer connection.Close()

	err = l.bind(connection)
	if err != nil {
		return err
	}

	result, err := connection.Search(ldap.NewSearchRequest(
		l.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		l.buildUserSearchFilter(username),
		[]string{"dn"},
		nil,
	))

	if err != nil {
		return fmt.Errorf("failed to find user. %s", err)
	}

	if len(result.Entries) < 1 {
		return fmt.Errorf("user does not exist")
	}

	if len(result.Entries) > 1 {
		return fmt.Errorf("too many entries returned")
	}

	if err := connection.Bind(result.Entries[0].DN, password); err != nil {
		return fmt.Errorf("failed to auth. %s", err)
	}

	return nil
}

func (l *LDAPUsersRepository) bind(conn *ldap.Conn) error {
	if l.config.BindPassword != nil {
		return conn.Bind(l.config.BindUser, *l.config.BindPassword)
	} else {
		return conn.UnauthenticatedBind(l.config.BindUser)
	}
}

func (l *LDAPUsersRepository) retrieveUserSet(conn *ldap.Conn) (map[string]models.User, error) {
	filter := ""
	if l.config.UserFilter != nil {
		filter = *l.config.UserFilter
	}

	users := make(map[string]models.User)
	pagingControl := ldap.NewControlPaging(PageSize)

	for {
		request := ldap.NewSearchRequest(
			l.config.BaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			filter,
			[]string{},
			[]ldap.Control{pagingControl},
		)
		response, err := conn.Search(request)
		if err != nil {
			return nil, err
		}

		for _, entry := range response.Entries {
			userId := entry.GetAttributeValue(l.config.UserAttribute)
			email := entry.GetAttributeValue(l.config.EmailAttribute)
			if userId != "" {
				users[userId] = models.User{Email: email, Username: userId}
			}
		}

		updatedControl := ldap.FindControl(response.Controls, ldap.ControlTypePaging)
		if ctrl, ok := updatedControl.(*ldap.ControlPaging); ctrl != nil && ok && len(ctrl.Cookie) != 0 {
			pagingControl.SetCookie(ctrl.Cookie)
			continue
		}
		// If no new paging information is available or the cookie is empty, we
		// are done with the pagination.
		break
	}

	return users, nil
}

func (l *LDAPUsersRepository) buildUserSearchFilter(username string) string {
	userCondition := fmt.Sprintf("(%s=%s)", l.config.UserAttribute, username)
	classCondition := fmt.Sprintf("(objectClass=%s)", l.config.UserClass)
	userFilter := ""
	if l.config.UserFilter != nil {
		userFilter = *l.config.UserFilter
	}

	return fmt.Sprintf("(&%s%s%s)", classCondition, userCondition, userFilter)
}
