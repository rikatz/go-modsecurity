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

extern void serverlogCallback_cgo();
*/
import "C"

import (
	"log"
	"sync"
	"unsafe"
)

var loggers = &loggerCollection{
	&sync.RWMutex{},
	make(map[uintptr]func(msg string), 0),
}

type loggerCollection struct {
	*sync.RWMutex

	callbacks map[uintptr]func(msg string)
}

type callbackInfo struct {
	logCallbackId uintptr
}

//export serverLogCallback
func serverLogCallback(info uint, data *C.char) {
	loggers.RLock()
	defer loggers.RUnlock()

	callback, ok := loggers.callbacks[uintptr(info)]
	if !ok {
		log.Printf("No logger found with callback id %d", info)
		return
	}

	callback(C.GoString(data))
}

func (m *Modsecurity) registerServerLogCallback(callback func(string)) {
	loggers.Lock()
	defer loggers.Unlock()

	m.logCallbackId = uintptr(unsafe.Pointer(m))
	loggers.callbacks[m.logCallbackId] = callback

	C.msc_set_log_cb(m.modsec, (C.ModSecLogCb)(unsafe.Pointer(C.serverlogCallback_cgo)))
}

func (m *Modsecurity) unregisterServerCallback() {
	loggers.Lock()
	defer loggers.Unlock()

	delete(loggers.callbacks, m.logCallbackId)
}
