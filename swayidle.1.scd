swayidle(1)

# NAME

swayidle - Idle manager for Wayland

# SYNOPSIS

*swayidle* [options] [events...]

# OPTIONS

*-h*
	Show help message and quit.

*-d*
	Enable debug output.

*-w*
	Wait for command to finish executing before continuing, helpful for ensuring
	that a *before-sleep* command has finished before the system goes to sleep.

	Note: using this option causes swayidle to block until the command finishes.

# DESCRIPTION

swayidle listens for idle activity on your Wayland compositor and executes tasks
on various idle-related events. You can specify any number of events at the
command line.

Sending SIGUSR1 to swayidle will immediately enter idle state.

# EVENTS

*timeout* <timeout> <timeout command> [resume <resume command>]
	Execute _timeout command_ if there is no activity for <timeout> seconds.

	If you specify "resume <resume command>", _resume command_ will be run when
	there is activity again.

*before-sleep* <command>
	If built with systemd support, executes _command_ before systemd puts the
	computer to sleep.

	Note: this only delays sleeping up to the limit set in *logind.conf(5)* by
	the option InhibitDelayMaxSec. A command that has not finished by then will
	continue running after resuming from sleep.

*after-resume* <command>
	If built with systemd support, executes _command_ after logind signals that the
	computer resumed from sleep.

*lock* <command>
	If built with systemd support, executes _command_ when logind signals that the
	session should be locked

*unlock* <command>
	If built with systemd support, executes _command_ when logind signals that the
	session should be unlocked

*idlehint* <timeout>
	If built with systemd support, set IdleHint to indcate an idle logind/elogind
	session after <timeout> seconds. Adding an idlehint event will also cause
	swayidle to call SetIdleHint(false) when run, on resume, unlock, etc.

All commands are executed in a shell.

# EXAMPLE

```
swayidle -w \
	timeout 300 'swaylock -f -c 000000' \
	timeout 600 'swaymsg "output * dpms off"' \
		resume 'swaymsg "output * dpms on"' \
	before-sleep 'swaylock -f -c 000000'
```

This will lock your screen after 300 seconds of inactivity, then turn off your
displays after another 300 seconds, and turn your screens back on when resumed.
It will also lock your screen before your computer goes to sleep.

To make sure swayidle waits for swaylock to lock the screen before it releases the
inhibition lock, the *-w* options is used in swayidle, and *-f* in swaylock.

# AUTHORS

Maintained by Drew DeVault <sir@cmpwn.com>, who is assisted by other open
source contributors. For more information about swayidle development, see
https://github.com/swaywm/swayidle.

# SEE ALSO

*sway*(5) *swaymsg*(1) *sway-input*(5) *sway-output*(5) *sway-bar*(5) *loginctl*(1)
