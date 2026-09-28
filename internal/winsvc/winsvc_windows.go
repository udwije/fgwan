//go:build windows

// Package winsvc runs fgwan under the Windows Service Control Manager.
//
// The SCM integration is implemented directly on advapi32, in the same spirit
// as the DPAPI credential store: it keeps the binary free of third-party
// modules, so `go build` still works on an air-gapped host. The surface used
// here is small and stable — three calls and two structures.
package winsvc

import (
	"errors"
	"fmt"
	"sync"
	"syscall"
	"unsafe"
)

// ErrNotService is returned when the process was not started by the SCM.
// Callers should fall back to running in the foreground.
var ErrNotService = errors.New("winsvc: not started by the service control manager")

var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procStartServiceCtrlDispatcher   = advapi32.NewProc("StartServiceCtrlDispatcherW")
	procRegisterServiceCtrlHandlerEx = advapi32.NewProc("RegisterServiceCtrlHandlerExW")
	procSetServiceStatus             = advapi32.NewProc("SetServiceStatus")
)

// Win32 service constants.
const (
	serviceWin32OwnProcess = 0x00000010

	serviceStopped      = 1
	serviceStartPending = 2
	serviceStopPending  = 3
	serviceRunning      = 4

	serviceAcceptStop     = 0x00000001
	serviceAcceptShutdown = 0x00000004

	serviceControlStop        = 1
	serviceControlInterrogate = 4
	serviceControlShutdown    = 5

	noError                 = 0
	errorCallNotImplemented = 120

	// Returned by StartServiceCtrlDispatcher when the process was launched
	// from a console rather than by the SCM.
	errFailedServiceControllerConnect = 1063
)

// serviceStatus mirrors the Win32 SERVICE_STATUS structure.
type serviceStatus struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

// serviceTableEntry mirrors the Win32 SERVICE_TABLE_ENTRYW structure.
type serviceTableEntry struct {
	Name *uint16
	Proc uintptr
}

// Callbacks are created once: syscall.NewCallback draws from a fixed-size
// table, so minting them per invocation is a slow leak in a long-lived
// process. They are also invoked by the SCM on threads we do not own, so the
// state they touch lives at package scope behind a mutex.
var (
	handlerPtr     = syscall.NewCallback(handler)
	serviceMainPtr = syscall.NewCallback(serviceMain)
)

var (
	mu       sync.Mutex
	handle   uintptr
	status   serviceStatus
	name     string
	work     func(stop <-chan struct{})
	stopCh   chan struct{}
	stopOnce sync.Once
)

// setState reports a new state to the SCM.
func setState(state, accepted, waitHint, checkpoint uint32) {
	mu.Lock()
	defer mu.Unlock()
	status.ServiceType = serviceWin32OwnProcess
	status.CurrentState = state
	status.ControlsAccepted = accepted
	status.WaitHint = waitHint
	status.CheckPoint = checkpoint
	if handle != 0 {
		procSetServiceStatus.Call(handle, uintptr(unsafe.Pointer(&status)))
	}
}

// resend repeats the current status, which is all an INTERROGATE asks for.
func resend() {
	mu.Lock()
	defer mu.Unlock()
	if handle != 0 {
		procSetServiceStatus.Call(handle, uintptr(unsafe.Pointer(&status)))
	}
}

// requestStop unblocks the worker. It is safe to call more than once: a stop
// request can race with a system shutdown.
func requestStop() {
	stopOnce.Do(func() { close(stopCh) })
}

// handler receives SCM control codes.
func handler(control, eventType, eventData, context uintptr) uintptr {
	switch control {
	case serviceControlInterrogate:
		resend()
		return noError

	case serviceControlStop, serviceControlShutdown:
		// 20 s of grace: the HTTP server is given 5 s to drain and the
		// collector stops on the next tick, so this is generous on purpose.
		setState(serviceStopPending, 0, 20000, 1)
		requestStop()
		return noError
	}
	// Anything else is genuinely not implemented, which is what the SCM
	// expects to hear rather than a bare success.
	return errorCallNotImplemented
}

// serviceMain is the SCM entry point for the service.
func serviceMain(argc uintptr, argv uintptr) uintptr {
	h, _, _ := procRegisterServiceCtrlHandlerEx.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(name))),
		handlerPtr,
		0,
	)
	if h == 0 {
		// Without a status handle the SCM cannot be told anything, so there
		// is nothing useful left to do.
		return 0
	}
	mu.Lock()
	handle = h
	mu.Unlock()

	setState(serviceStartPending, 0, 15000, 1)
	setState(serviceRunning, serviceAcceptStop|serviceAcceptShutdown, 0, 0)

	// Run the real work on this thread; it returns when stopCh closes.
	func() {
		defer func() {
			// A panic in the collector must still leave the SCM with a
			// definite answer, or the service hangs in "stopping".
			if r := recover(); r != nil {
				mu.Lock()
				status.Win32ExitCode = 1
				mu.Unlock()
			}
		}()
		work(stopCh)
	}()

	setState(serviceStopped, 0, 0, 0)
	return 0
}

// Run hands control to the SCM and calls work once the service is running.
// work must return when its stop channel is closed.
//
// If the process was not launched by the SCM, Run returns ErrNotService
// without calling work, so the caller can run in the foreground instead.
func Run(serviceName string, fn func(stop <-chan struct{})) error {
	mu.Lock()
	name = serviceName
	work = fn
	stopCh = make(chan struct{})
	stopOnce = sync.Once{}
	mu.Unlock()

	// The table is NUL-terminated by a zero entry.
	table := []serviceTableEntry{
		{Name: syscall.StringToUTF16Ptr(serviceName), Proc: serviceMainPtr},
		{Name: nil, Proc: 0},
	}

	r, _, err := procStartServiceCtrlDispatcher.Call(uintptr(unsafe.Pointer(&table[0])))
	if r == 0 {
		if errno, ok := err.(syscall.Errno); ok && errno == errFailedServiceControllerConnect {
			return ErrNotService
		}
		return fmt.Errorf("winsvc: StartServiceCtrlDispatcher: %w", err)
	}
	return nil
}
