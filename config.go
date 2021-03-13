package main

import (
	"flag"

	"github.com/vharitonsky/iniflags"
)

var (
	appVersion = "unknown"
	buildTime  = "unknown"
)

var (
	logFile           = flag.String("logfile", "", "Path to logfile")
	logFormat         = flag.String("log_format", "default", "Log output format")
	logLevel          = flag.String("log_level", "info", "Minimum log level to output")
	hostName          = flag.String("hostname", "localhost.localdomain", "Server hostname")
	welcomeMsg        = flag.String("welcome_msg", "", "Welcome message for SMTP session")
	listen            = flag.String("listen", "127.0.0.1:25 [::1]:25", "Address and port to listen for incoming SMTP")
	localForceTLS     = flag.Bool("local_forcetls", false, "Force STARTTLS (needs local_cert and local_key)")
	allowedNets       = flag.String("allowed_nets", "127.0.0.1/8 ::1/128", "Networks allowed to send mails")
	allowedSender     = flag.String("allowed_sender", "", "Regular expression for valid FROM EMail addresses")
	allowedRecipients = flag.String("allowed_recipients", "", "Regular expression for valid TO EMail addresses")
	remoteHost        = flag.String("remote_host", "smtp.gmail.com:587", "Outgoing SMTP server")
	remoteUser        = flag.String("remote_user", "", "Username for authentication on outgoing SMTP server")
	remotePass        = flag.String("remote_pass", "", "Password for authentication on outgoing SMTP server")
	remoteAuth        = flag.String("remote_auth", "plain", "Auth method on outgoing SMTP server (plain, login)")
	remoteSender      = flag.String("remote_sender", "", "Sender e-mail address on outgoing SMTP server")
	versionInfo       = flag.Bool("version", false, "Show version information")
)

func ConfigLoad() {
	iniflags.Parse()

	// Set up logging as soon as possible
	setupLogger()
}
