//go:build linux

package main

import "log/syslog"

func syslogWriter() (*syslog.Writer, error) {
	return syslog.New(syslog.LOG_AUTH|syslog.LOG_INFO, "portash")
}
