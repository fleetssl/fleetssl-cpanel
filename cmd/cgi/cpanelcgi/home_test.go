package cpanelcgi

import "testing"

func TestGetDomainStatus(t *testing.T) {
	/*
		possible statuses:

		on certs stored in the account data:
		- no key or cert, broken
		- key, but no cert, polling

		on certs installed,
		- if self signed, not installed
		- if account id doesnt match installed id, not installed
		- check expired

	*/
}
