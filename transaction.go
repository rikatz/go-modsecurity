// Diato - Reverse Proxying for Hipsters
//
// Copyright 2016-2017 Dolf Schimmel
// Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
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

#include <stdint.h>
#include "modsecurity/modsecurity.h"
#include "modsecurity/transaction.h"

Transaction *msc_new_transaction_cgo(ModSecurity *ms, Rules *rules, long logCbData) {
    return msc_new_transaction(ms, rules, (void*)(intptr_t)logCbData);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"unsafe"
)

// Represents the inspection on an entire request.
//
// An instance of the transaction struct represents
// an entire request, on its different phases.
type transaction struct {
	ruleset *RuleSet

	msc_txn     *C.struct_Transaction_t
	itemsToFree []unsafe.Pointer
}

// Create a new transaction for a given configuration and ModSecurity core.
//
// The transaction is the unit that will be used the inspect every request. It holds
// all the information for a given request.
//
// Remember to cleanup the transaction when the transaction is complete using Cleanup()
func (r *RuleSet) NewTransaction(remoteAddr, localAddr string) (*transaction, error) {
	remoteIp, remotePort, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("Could not parse remote address: %s", err)
	}

	remotePortInt, err := strconv.Atoi(remotePort)
	if err != nil {
		return nil, fmt.Errorf("Could not convert remote port '%s' to int: %s", remotePort, err.Error())
	}

	localIp, localPort, err := net.SplitHostPort(localAddr)
	if err != nil {
		return nil, fmt.Errorf("Could not parse remote address: %s", err)
	}

	localPortInt, err := strconv.Atoi(localPort)
	if err != nil {
		return nil, fmt.Errorf("Could not convert local port '%s' to int: %s", localPort, err.Error())
	}

	msc_txn := C.msc_new_transaction_cgo(r.modsec.modsec, r.msc_rules, C.long(r.modsec.logCallbackId))
	if msc_txn == nil {
		return nil, fmt.Errorf("Could not initialize transaction")
	}

	cRemoteIp := C.CString(remoteIp)
	cLocalIp := C.CString(localIp)

	if C.msc_process_connection(msc_txn, cRemoteIp, C.int(remotePortInt), cLocalIp, C.int(localPortInt)) != 1 {
		C.free(unsafe.Pointer(cRemoteIp))
		C.free(unsafe.Pointer(cLocalIp))
		return nil, errors.New("could not process connection")
	}

	txn := &transaction{
		ruleset: r,
		msc_txn: msc_txn,
	}
	txn.deferFree(unsafe.Pointer(cRemoteIp), unsafe.Pointer(cLocalIp))
	return txn, nil
}

// Perform the analysis on the URI and all the query string variables.
//
// There is no direct connection between this function and any phase of
// the SecLanguage's phases. It is something that may occur between the
// SecLanguage phase 1 and 2.
func (txn *transaction) ProcessUri(uri, method, httpVersion string) error {
	cUri := C.CString(uri)
	cMethod := C.CString(method)
	cHttpVersion := C.CString(httpVersion)
	txn.deferFree(unsafe.Pointer(cUri),
		unsafe.Pointer(cMethod),
		unsafe.Pointer(cHttpVersion),
	)

	if C.msc_process_uri(txn.msc_txn, cUri, cMethod, cHttpVersion) != 1 {
		return errors.New("Could not process URI")
	}
	return nil
}

// With this function it is possible to feed ModSecurity with a request header.
func (txn *transaction) AddRequestHeader(key, value []byte) error {
	// Per Modsecurity doc, key and value are NULL ended
	// Ref: https://github.com/SpiderLabs/ModSecurity/blob/v3.0.4/src/transaction.cc#L2034
	key = append(key, 0)
	value = append(value, 0)

	cKey := C.CBytes(key)
	cValue := C.CBytes(value)
	txn.deferFree(unsafe.Pointer(cKey), unsafe.Pointer(cValue))

	if C.msc_add_request_header(txn.msc_txn,
		(*C.uchar)(unsafe.Pointer(cKey)),
		(*C.uchar)(unsafe.Pointer(cValue))) != 1 {
		return errors.New("Could not add request header")
	}
	return nil
}

// This function perform the analysis on the request headers, notice however
// that the headers should be added prior to the execution of this function.
//
// Remember to check for a possible intervention.
func (txn *transaction) ProcessRequestHeaders() error {
	if C.msc_process_request_headers(txn.msc_txn) != 1 {
		return errors.New("Could not process request headers")
	}
	return nil
}

// Adds request body to be inspected.
//
// With this function it is possible to feed ModSecurity with data for
// inspection regarding the request body.
func (txn *transaction) AppendRequestBody(bodyBuf []byte) error {
	bodyBufC := C.CBytes(append(bodyBuf, '\n'))
	txn.deferFree(unsafe.Pointer(bodyBufC))

	if 1 != C.msc_append_request_body(txn.msc_txn,
		(*C.uchar)(unsafe.Pointer(bodyBufC)),
		(C.size_t)(len(bodyBuf))) {
		return errors.New("Could not append Request Body")
	}

	return nil
}

// Perform the analysis on the request body (if any)
// This function perform the analysis on the request body. It is optional to
// call that function. If this API consumer already know that there isn't a
// body for inspect it is recommended to skip this step.
//
// It is necessary to "append" the request body prior to the execution of this function.
//
// Remember to check for a possible intervention.
func (txn *transaction) ProcessRequestBody() error {
	if C.msc_process_request_body(txn.msc_txn) != 1 {
		return errors.New("Could not process Request Body")
	}

	return nil
}

// Logging all information relative to this transaction.
//
// At this point there is not need to hold the connection,
// the response can be delivered prior to the execution of
// this method.
func (txn *transaction) ProcessLogging() error {
	if C.msc_process_logging(txn.msc_txn) != 1 {
		return errors.New("Could not Process Logging")
	}
	return nil
}

func (txn *transaction) ShouldIntervene() bool {
	intervention := C.struct_ModSecurityIntervention_t{}

	if C.msc_intervention(txn.msc_txn, &intervention) == 0 {
		return false
	}
	//fmt.Printf("%v\n", C.GoString(intervention.log))
	return true
}

func (txn *transaction) Cleanup() {
	C.msc_transaction_cleanup(txn.msc_txn)
	txn.msc_txn = nil
	for _, freeMe := range txn.itemsToFree {
		C.free(freeMe)
	}
}

func (txn *transaction) deferFree(addToList ...unsafe.Pointer) {
	txn.itemsToFree = append(txn.itemsToFree, addToList...)
}
