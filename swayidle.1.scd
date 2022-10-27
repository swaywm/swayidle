swayidle(1)

# NAME

swayidle - Idle manager for Wayland

# SYNOPSIS

*swayidle* [options] [events...]

# OPTIONS

*-C* <path>
	The config file to use. By default, the following paths are checked in the following order: $XDG_CONFIG_HOME/swayidle/config, $HOME/swayidle/config
	Config file entries are events as described in the EVENTS section.
	Specifying events in the config and as arguments is not mutually exclusive.

*-h*
	Show help message and quit.

*-d*
	Enable debug output.

*-w*
	Wait for command to finish executing before continuing.

	Note: using this option causes swayidle to block until the command finishes.

*-S* <seat-name>
	Specify which seat to use. By default, if no name is specified, an arbitrary seat will be picked instead.

# DESCRIPTION

swayidle listens for idle activity on your Wayland compositor and executes tasks
on various idle-related events. You can specify any number of events at the
command line and in the config file.

# EVENTS

*timeout* <timeout> <timeout command> [resume <resume command>]
	Execute _timeout command_ if there is no activity for <timeout> seconds.

	If you specify "resume <resume command>", _resume command_ will be run when
	there is activity again.

All commands are executed in a shell.

# SIGNALS

swayidle responds to the following signals:

*SIGTERM, SIGINT*
	Run all pending resume commands. When finished swayidle will terminate.

*SIGUSR1*
	Immediately enter idle state.

# EXAMPLE

```
swayidle -w \\
	timeout 300 'swaylock -f -c 000000' \\
	timeout 600 'swaymsg "output * dpms off"' \\
		resume 'swaymsg "output * dpms on"' \\
```

This will lock your screen after 300 seconds of inactivity, then turn off your
displays after another 300 seconds, and turn your screens back on when resumed.

To make sure swayidle waits for swaylock to lock the screen before it releases the
inhibition lock, the *-w* options is used in swayidle, and *-f* in swaylock.

# AUTHORS

Maintained by Drew DeVault <sir@cmpwn.com>, who is assisted by other open
source contributors. For more information about swayidle development, see
https://github.com/swaywm/swayidle.

# SEE ALSO

*sway*(5) *swaymsg*(1) *sway-input*(5) *sway-output*(5) *sway-bar*(5) *loginctl*(1)
