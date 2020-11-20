package modsecurity

import (
	"testing"
)

func TestNewModsecurity(t *testing.T) {
	ms, err := NewModsecurity()
	if err != nil {
		t.Errorf("NewModsecurity() error = %v", err)
	}

	if ms == nil {
		t.Errorf("expected Modsecurity instance but none returned")
	}
}

func TestWhoAmI(t *testing.T) {
	ms, err := NewModsecurity()
	if err != nil {
		t.Errorf("unexpected NewModsecurity() error: %v", err)
	}

	expectedVersion := "ModSecurity v3.0.3 (Linux)"
	whoAmI := ms.WhoAmI()
	if whoAmI != expectedVersion {
		t.Errorf("expected %v but %v returned", expectedVersion, whoAmI)
	}
}

/*
func TestModsecurity_SetServerLogCallback(t *testing.T) {
	type fields struct {
		modsec        *C.struct_ModSecurity_t
		logCallbackId uintptr
	}
	type args struct {
		callback func(string)
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Modsecurity{
				modsec:        tt.fields.modsec,
				logCallbackId: tt.fields.logCallbackId,
			}
			m.SetServerLogCallback(tt.args.callback)
		})
	}
}
*/
/*
func TestModsecurity_WhoAmI(t *testing.T) {
	type fields struct {
		modsec        *C.struct_ModSecurity_t
		logCallbackId uintptr
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		// TODO: Add test cases.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Modsecurity{
				modsec:        tt.fields.modsec,
				logCallbackId: tt.fields.logCallbackId,
			}
			if got := m.WhoAmI(); got != tt.want {
				t.Errorf("Modsecurity.WhoAmI() = %v, want %v", got, tt.want)
			}
		})
	}
}
*/
