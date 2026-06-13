package identity

import "testing"

func TestFromARN_Valid(t *testing.T) {
	cases := map[string]string{
		"arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_AdministratorAccess_abc/alice@example.com": "alice",
		"arn:aws:sts::823091238322:assumed-role/AWSReservedSSO_PowerUserAccess_x/DL6544-A@engie.com":       "dl6544-a",
		"arn:aws:sts::123456789012:assumed-role/workstation-role/i-00c45ce9e5a87cd60":                      "i-00c45ce9e5a87cd60",
	}
	for arn, want := range cases {
		got, err := FromARN(arn)
		if err != nil {
			t.Errorf("FromARN(%q) unexpected error: %v", arn, err)
			continue
		}
		if got != want {
			t.Errorf("FromARN(%q) = %q, want %q", arn, got, want)
		}
	}
}

func TestFromARN_Rejected(t *testing.T) {
	bad := []string{
		"not-an-arn",                             // no slash
		"arn:aws:sts::1:assumed-role/role/",      // trailing slash (empty session name)
		"arn:aws:sts::1:assumed-role/role/@@@",   // empties out
		"arn:aws:sts::1:assumed-role/role/root",  // reserved
		"arn:aws:sts::1:assumed-role/role/ec2-user", // reserved
	}
	for _, arn := range bad {
		if got, err := FromARN(arn); err == nil {
			t.Errorf("FromARN(%q) = %q, want error", arn, got)
		}
	}
}

func TestSanitize_RejectsAmbiguousAndUnsafe(t *testing.T) {
	reject := []string{
		"Alice.Smith+test@example.com", // dots/plus would be silently stripped -> reject
		"a.l.i.c.e@example.com",        // would merge into "alice" -> reject
		"-foo@example.com",             // leading dash (arg-injection)
		"1abc@example.com",             // leading digit
		"root",                         // reserved
		"daemon",                       // reserved
		"",                             // empty
		"averyveryveryveryveryverylongusername33", // > 32 chars -> reject (no silent truncation)
	}
	for _, in := range reject {
		if got, err := Sanitize(in); err == nil {
			t.Errorf("Sanitize(%q) = %q, want error", in, got)
		}
	}
}

func TestSanitize_AcceptsCleanNames(t *testing.T) {
	ok := map[string]string{
		"alice@example.com":  "alice",
		"DL6544-A@engie.com": "dl6544-a",
		"bob":                "bob",
		"jane_doe":           "jane_doe",
	}
	for in, want := range ok {
		got, err := Sanitize(in)
		if err != nil {
			t.Errorf("Sanitize(%q) unexpected error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("Sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}
