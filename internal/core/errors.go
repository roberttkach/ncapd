package core

import "errors"

var ErrInvalidRequest = errors.New("invalid check request")
var ErrNoAdapter = errors.New("no adapter registered for check type")
var ErrTimeout = errors.New("check timed out")
var ErrDNSFiltered = errors.New("DNS query returned no result or NXDOMAIN")
var ErrSNIRejected = errors.New("TLS handshake rejected (SNI inspection)")
var ErrRSTReceived = errors.New("TCP RST received during handshake")
