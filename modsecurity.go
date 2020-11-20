// Diato - Reverse Proxying for Hipsters
//
// Copyright 2016-2017 Dolf Schimmel
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package modsecurity

/*
#cgo CFLAGS: -g -Wall
#cgo LDFLAGS: -lmodsecurity

#include "modsecurity/modsecurity.h"
#include "modsecurity/transaction.h"
#include "modsecurity/rules.h"
*/
import "C"

import (
	"errors"
	"runtime"
)

type Modsecurity struct {
	modsec        *C.struct_ModSecurity_t
	logCallbackId uintptr
}

func NewModsecurity() (*Modsecurity, error) {
	modsec := C.msc_init()

	if modsec == nil {
		return nil, errors.New("Could not initialize Mod Security")
	}

	C.msc_set_connector_info(modsec, C.CString("go-modsecurity v0.0.1"))

	ret := &Modsecurity{
		modsec: modsec,
	}
	runtime.SetFinalizer(ret, finalizeModSecurity)

	return ret, nil
}

func (m *Modsecurity) SetServerLogCallback(callback func(string)) {
	m.registerServerLogCallback(callback)
}

// Return information about this ModSecurity version and platform.
func (m *Modsecurity) WhoAmI() string {
	return C.GoString(C.msc_who_am_i(m.modsec))
}

func finalizeModSecurity(m *Modsecurity) {
	m.unregisterServerCallback()
}
