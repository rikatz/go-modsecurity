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

#include <stdio.h>
#include <stdlib.h>

#include "modsecurity/rules.h"

int msc_rules_add_file_bridge(Rules *rules, const char *file, char *error) {
	const char *err = NULL;
	int ret;

	if ((ret = msc_rules_add_file(rules, file, &err)) < 0) {
		strncpy(error, err, 1024);
    }
    return ret;
}

int msc_rules_add_bridge(Rules *rules, const char *plain_rules, char *error) {
	const char *err = NULL;
	int ret;

	if ((ret = msc_rules_add(rules, plain_rules, &err)) < 0) {
		strncpy(error, err, 1024);
    }
    return ret;
}

*/
import "C"
import (
	"fmt"
	"strings"
	"unsafe"
)

type RuleSet struct {
	modsec *Modsecurity

	msc_rules *C.struct_Rules_t
}

func (m *Modsecurity) NewRuleSet() *RuleSet {
	rules := C.msc_create_rules_set()

	return &RuleSet{
		modsec:    m,
		msc_rules: rules,
	}
}

func (r *RuleSet) AddFile(path string) error {
	fileuri := C.CString(path)
	defer C.free(unsafe.Pointer(fileuri))

	err := C.CString(strings.Repeat(string('\x00'), 1024))
	defer C.free(unsafe.Pointer(err))

	if ret := C.msc_rules_add_file_bridge(r.msc_rules, fileuri, err); ret < 0 {
		return fmt.Errorf("Error loading rules: %s", C.GoString(err))
	}
	return nil
}

func (r *RuleSet) AddRules(rules string) error {

	cRules := C.CString(rules)
	defer C.free(unsafe.Pointer(cRules))

	err := C.CString(strings.Repeat(string('\x00'), 1024))
	defer C.free(unsafe.Pointer(err))

	if ret := C.msc_rules_add_bridge(r.msc_rules, cRules, err); ret < 0 {
		return fmt.Errorf("Error loading rules: %s", C.GoString(err))
	}
	return nil
}
