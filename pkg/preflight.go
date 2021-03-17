package preflight

import (
	"net"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var preflightErrorCount int = 0
var preflightCmd = &cobra.Command{
	Use:        "init",
	Aliases:    []string{},
	SuggestFor: []string{},
	Short:      "Checks for conflicts on the host",
	Long:       `This checks for conflicts on the host and reports issues for user resolution.`,
	Example:    "keanu init --preflight",
	Run: func(cmd *cobra.Command, args []string) {
		logrus.Info("keanu begin preflight checks...")
		logrus.WithFields(logrus.Fields{
			"PortCheck":    portCheck(),
			"FWRules":      firewallRulesCheck(),
			"SystemdCheck": systemdCheck(),
		}).Info("Preflight Summary")
		if preflightErrorCount == 0 {
			logrus.Infof("No preflight conflicts detected, you are safe to continue.")
		} else {
			logrus.Fatal("Preflight errors found, please remediate before continuing.")
		}
	},
}

func init() {
	preflightCmd.AddCommand(preflightCmd)
}

func portCheck() int {
	logrus.Info("Starting Port Checks")
	// set the error count to 0
	porterrorcount := 0

	for port, protocolArray := range portlist {
		for _, protocol := range protocolArray {
			logrus.Debugf("Testing port %s on protocol %s", port, protocol)
			//check if you can listen on this port on TCP
			if protocol == "tcp" {
				if t, err := net.Listen(protocol, ":"+port); err == nil {
					// If this returns an error, then something else is listening on this port
					if err != nil {
						if logrus.GetLevel().String() == "debug" {
							logrus.Warnf("Port check  %s/%s is in use", port, protocol)
						}
						porterrorcount += 1
					}
					t.Close()

				}
			} else if protocol == "udp" {
				if u, err := net.ListenPacket(protocol, ":"+port); err == nil {
					// If this returns an error, then something else is listening on this port
					if err != nil {
						if logrus.GetLevel().String() == "debug" {
							logrus.Warnf("Port check  %s/%s is in use", port, protocol)
						}
						porterrorcount += 1
					}
					u.Close()

				}
			}
		}
	}

	// Display that no errors were found
	if porterrorcount > 0 {
		preflightErrorCount += 1
	}
	logrus.WithFields(logrus.Fields{"Port Issues": porterrorcount}).Info("Preflight checks for Ports")
	return porterrorcount
}

func systemdCheck() int {
	// set the error count to 0
	svcerrorcount := 0
	logrus.Info("Starting Systemd Checks")

	for _, s := range systemdsvc {
		if isServiceRunning(s) {
			logrus.Debug("Service " + s + " is running")
			svcerrorcount += 1
			if fix {
				logrus.Info("STOPPING/DISABLING SERVICE: " + s)
				stopService(s)
				disableService(s)
			}
		}
	}
	// Display that no errors were found
	if svcerrorcount > 0 {
		preflightErrorCount += 1
	}
	logrus.WithFields(logrus.Fields{"Systemd Issues": svcerrorcount}).Info("Preflight checks for Systemd")
	return svcerrorcount

}

func firewallRulesCheck() int {
	// set the error count to 0
	fwerrorcount := 0
	fwfixCount := 0

	logrus.Info("Running firewall checks")
	// Check if firewalld service is running
	if !isServiceRunning("firewalld.service") {
		//		fwerrorcount += 1
		logrus.Debug("Service firewalld.service is NOT running")
		if fix {
			startService("firewalld.service")
			enableService("firewalld.service")
		}
	}

	// get the current firewall rules on the host and set it to "s"
	s := getCurrentFirewallRules()
	// loop through each firewall rule:
	// If there's a match, that means the rule is there and nothing needs to be done.
	// If it's NOT there, it needs to be enabled (if requested)
	for port, protocolArray := range portlist {
		for _, protocol := range protocolArray {
			_, found := find(s, port+"/"+protocol)
			if !found {
				if logrus.GetLevel().String() == "debug" {
					//this is a bit weird but only want to log these in debug mode.
					//BUT using WARN so they show up yellow
					logrus.Warnf("Firewall rule %s not found", port+"/"+protocol)
				}
				fwerrorcount += 1
				if fix {
					logrus.Info("OPENING PORT: " + port + "/" + protocol)
					openPort(port + "/" + protocol)
					fwfixCount++
				}
			}
		}
	}

	// Display that no errors were found
	if fwerrorcount > 0 {
		preflightErrorCount += 1
	}
	if fix {
		logrus.WithFields(logrus.Fields{"Firewall Issues": fwerrorcount, "Firewall rules added": fwfixCount}).Info("Preflight checks for Firewall")
	} else {
		logrus.WithFields(logrus.Fields{"Firewall Issues": fwerrorcount}).Info("Preflight checks for Firewall")
	}
	return fwerrorcount
}
