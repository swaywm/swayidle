#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wayland-client-protocol.h>
#include <wayland-client.h>
#include <wayland-server.h>
#include <wayland-util.h>
#include "config.h"
#include "idle-client-protocol.h"
#if HAVE_SYSTEMD
#include <systemd/sd-bus.h>
#include <systemd/sd-login.h>
#elif HAVE_ELOGIND
#include <elogind/sd-bus.h>
#include <elogind/sd-login.h>
#endif

static struct org_kde_kwin_idle *idle_manager = NULL;
static struct wl_seat *seat = NULL;

struct swayidle_state {
	struct wl_display *display;
	struct wl_event_loop *event_loop;
	struct wl_list timeout_cmds; // struct swayidle_timeout_cmd *
	char *before_sleep_cmd;
	char *after_resume_cmd;
	char *logind_lock_cmd;
	char *logind_unlock_cmd;
	bool logind_idlehint;
	bool wait;
} state;

struct swayidle_timeout_cmd {
	struct wl_list link;
	int timeout, registered_timeout;
	struct org_kde_kwin_idle_timeout *idle_timer;
	char *idle_cmd;
	char *resume_cmd;
	bool idlehint;
};

enum log_importance {
	LOG_DEBUG = 1,
	LOG_INFO = 2,
	LOG_ERROR = 3,
};

static enum log_importance verbosity = LOG_INFO;

static void swayidle_log(enum log_importance importance, const char *fmt, ...) {
	if (importance < verbosity) {
		return;
	}
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fprintf(stderr, "\n");
}

static void swayidle_log_errno(
		enum log_importance importance, const char *fmt, ...) {
	if (importance < verbosity) {
		return;
	}
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fprintf(stderr, ": %s\n", strerror(errno));
}

void sway_terminate(int exit_code) {
	wl_display_disconnect(state.display);
	wl_event_loop_destroy(state.event_loop);
	exit(exit_code);
}

static void cmd_exec(char *param) {
	swayidle_log(LOG_DEBUG, "Cmd exec %s", param);
	pid_t pid = fork();
	if (pid == 0) {
		if (!state.wait) {
			pid = fork();
		}
		if (pid == 0) {
			char *const cmd[] = { "sh", "-c", param, NULL, };
			execvp(cmd[0], cmd);
			swayidle_log_errno(LOG_ERROR, "execve failed!");
			exit(1);
		} else if (pid < 0) {
			swayidle_log_errno(LOG_ERROR, "fork failed");
			exit(1);
		}
		exit(0);
	} else if (pid < 0) {
		swayidle_log_errno(LOG_ERROR, "fork failed");
	} else {
		swayidle_log(LOG_DEBUG, "Spawned process %s", param);
		waitpid(pid, NULL, 0);
	}
}

#if HAVE_SYSTEMD || HAVE_ELOGIND
static int lock_fd = -1;
static struct sd_bus *bus = NULL;
static char *session_name = NULL;

static void acquire_sleep_lock(void) {
	sd_bus_message *msg = NULL;
	sd_bus_error error = SD_BUS_ERROR_NULL;
	int ret = sd_bus_call_method(bus, "org.freedesktop.login1",
			"/org/freedesktop/login1",
			"org.freedesktop.login1.Manager", "Inhibit",
			&error, &msg, "ssss", "sleep", "swayidle",
			"Setup Up Lock Screen", "delay");
	if (ret < 0) {
		swayidle_log(LOG_ERROR,
				"Failed to send Inhibit signal: %s", error.message);
		goto cleanup;
	}

	ret = sd_bus_message_read(msg, "h", &lock_fd);
	if (ret < 0) {
		errno = -ret;
		swayidle_log_errno(LOG_ERROR,
				"Failed to parse D-Bus response for Inhibit");
		goto cleanup;
	}

	// sd_bus_message_unref closes the file descriptor so we need
	// to copy it beforehand
	lock_fd = fcntl(lock_fd, F_DUPFD_CLOEXEC, 3);
	if (lock_fd >= 0) {
		swayidle_log(LOG_INFO, "Got sleep lock: %d", lock_fd);
	} else {
		swayidle_log_errno(LOG_ERROR, "Failed to copy sleep lock fd");
	}

cleanup:
	sd_bus_error_free(&error);
	sd_bus_message_unref(msg);
}

static void set_idle_hint(bool hint) {
	swayidle_log(LOG_DEBUG, "SetIdleHint %d", hint);
	sd_bus_message *msg = NULL;
	sd_bus_error error = SD_BUS_ERROR_NULL;
	int ret = sd_bus_call_method(bus, "org.freedesktop.login1",
			session_name, "org.freedesktop.login1.Session", "SetIdleHint",
			&error, &msg, "b", hint);
	if (ret < 0) {
		swayidle_log(LOG_ERROR,
				"Failed to send SetIdleHint signal: %s", error.message);
	}

	sd_bus_error_free(&error);
	sd_bus_message_unref(msg);
}

static int prepare_for_sleep(sd_bus_message *msg, void *userdata,
		sd_bus_error *ret_error) {
	/* "b" apparently reads into an int, not a bool */
	int going_down = 1;
	int ret = sd_bus_message_read(msg, "b", &going_down);
	if (ret < 0) {
		errno = -ret;
		swayidle_log_errno(LOG_ERROR,
				"Failed to parse D-Bus response for Inhibit: %s");
	}
	swayidle_log(LOG_DEBUG, "PrepareForSleep signal received %d", going_down);
	if (!going_down) {
		acquire_sleep_lock();
		if (state.after_resume_cmd) {
			cmd_exec(state.after_resume_cmd);
		}
		if (state.logind_idlehint) {
			set_idle_hint(false);
		}
		return 0;
	}

	if (state.before_sleep_cmd) {
		cmd_exec(state.before_sleep_cmd);
	}
	swayidle_log(LOG_DEBUG, "Prepare for sleep done");

	swayidle_log(LOG_INFO, "Releasing sleep lock %d", lock_fd);
	if (lock_fd >= 0) {
		close(lock_fd);
	}
	lock_fd = -1;

	return 0;
}
static int handle_lock(sd_bus_message *msg, void *userdata,
		sd_bus_error *ret_error) {
	swayidle_log(LOG_DEBUG, "Lock signal received");

	if (state.logind_lock_cmd) {
		cmd_exec(state.logind_lock_cmd);
	}
	swayidle_log(LOG_DEBUG, "Lock command done");

	return 0;
}

static int handle_unlock(sd_bus_message *msg, void *userdata,
		sd_bus_error *ret_error) {
	swayidle_log(LOG_DEBUG, "Unlock signal received");

	if (state.logind_idlehint) {
		set_idle_hint(false);
	}
	if (state.logind_unlock_cmd) {
		cmd_exec(state.logind_unlock_cmd);
	}
	swayidle_log(LOG_DEBUG, "Unlock command done");

	return 0;
}

static int dbus_event(int fd, uint32_t mask, void *data) {
	sd_bus *bus = data;

	if ((mask & WL_EVENT_HANGUP) || (mask & WL_EVENT_ERROR)) {
		sway_terminate(0);
	}

	int count = 0;
	if (mask & WL_EVENT_READABLE) {
		count = sd_bus_process(bus, NULL);
	}
	if (mask & WL_EVENT_WRITABLE) {
		sd_bus_flush(bus);
	}
	if (mask == 0) {
		sd_bus_flush(bus);
	}

	if (count < 0) {
		swayidle_log_errno(LOG_ERROR, "sd_bus_process failed, exiting");
		sway_terminate(0);
	}

	return count;
}

static void connect_to_bus(void) {
	int ret = sd_bus_default_system(&bus);
	sd_bus_message *msg = NULL;
	sd_bus_error error = SD_BUS_ERROR_NULL;
	pid_t my_pid = getpid();
	const char *session_name_tmp;
	if (ret < 0) {
		errno = -ret;
		swayidle_log_errno(LOG_ERROR, "Failed to open D-Bus connection");
		return;
	}
	struct wl_event_source *source = wl_event_loop_add_fd(state.event_loop,
		sd_bus_get_fd(bus), WL_EVENT_READABLE, dbus_event, bus);
	wl_event_source_check(source);
	ret = sd_bus_call_method(bus, "org.freedesktop.login1",
			"/org/freedesktop/login1",
			"org.freedesktop.login1.Manager", "GetSessionByPID",
			&error, &msg, "u", my_pid);
	if (ret < 0) {
		swayidle_log(LOG_ERROR,
				"Failed to find session name: %s", error.message);
		goto cleanup;
	}

	ret = sd_bus_message_read(msg, "o", &session_name_tmp);
	if (ret < 0) {
		swayidle_log(LOG_ERROR,
				"Failed to read session name\n");
		goto cleanup;
	}
	session_name = strdup(session_name_tmp);
cleanup:
	sd_bus_error_free(&error);
	sd_bus_message_unref(msg);
}

static void setup_sleep_listener(void) {
	int ret = sd_bus_match_signal(bus, NULL, "org.freedesktop.login1",
                "/org/freedesktop/login1", "org.freedesktop.login1.Manager",
                "PrepareForSleep", prepare_for_sleep, NULL);
	if (ret < 0) {
		errno = -ret;
		swayidle_log_errno(LOG_ERROR, "Failed to add D-Bus signal match : sleep");
		return;
	}
	acquire_sleep_lock();
}

static void setup_lock_listener(void) {
	int ret = sd_bus_match_signal(bus, NULL, "org.freedesktop.login1",
                session_name, "org.freedesktop.login1.Session",
                "Lock", handle_lock, NULL);
	if (ret < 0) {
		errno = -ret;
		swayidle_log_errno(LOG_ERROR, "Failed to add D-Bus signal match : lock");
		return;
	}
}

static void setup_unlock_listener(void) {
	int ret = sd_bus_match_signal(bus, NULL, "org.freedesktop.login1",
                session_name, "org.freedesktop.login1.Session",
                "Unlock", handle_unlock, NULL);
	if (ret < 0) {
		errno = -ret;
		swayidle_log_errno(LOG_ERROR, "Failed to add D-Bus signal match : unlock");
		return;
	}
}
#endif

static void handle_global(void *data, struct wl_registry *registry,
		uint32_t name, const char *interface, uint32_t version) {
	if (strcmp(interface, org_kde_kwin_idle_interface.name) == 0) {
		idle_manager =
			wl_registry_bind(registry, name, &org_kde_kwin_idle_interface, 1);
	} else if (strcmp(interface, wl_seat_interface.name) == 0) {
		seat = wl_registry_bind(registry, name, &wl_seat_interface, 1);
	}
}

static void handle_global_remove(void *data, struct wl_registry *registry,
		uint32_t name) {
	// Who cares
}

static const struct wl_registry_listener registry_listener = {
	.global = handle_global,
	.global_remove = handle_global_remove,
};

static const struct org_kde_kwin_idle_timeout_listener idle_timer_listener;

static void register_timeout(struct swayidle_timeout_cmd *cmd,
		int timeout) {
	if (cmd->idle_timer != NULL) {
		org_kde_kwin_idle_timeout_destroy(cmd->idle_timer);
		cmd->idle_timer = NULL;
	}
	if (timeout < 0) {
		swayidle_log(LOG_DEBUG, "Not registering idle timeout");
		return;
	}
	swayidle_log(LOG_DEBUG, "Register with timeout: %d", timeout);
	cmd->idle_timer =
		org_kde_kwin_idle_get_idle_timeout(idle_manager, seat, timeout);
	org_kde_kwin_idle_timeout_add_listener(cmd->idle_timer,
		&idle_timer_listener, cmd);
	cmd->registered_timeout = timeout;
}

static void handle_idle(void *data, struct org_kde_kwin_idle_timeout *timer) {
	struct swayidle_timeout_cmd *cmd = data;
	swayidle_log(LOG_DEBUG, "idle state");
#if HAVE_SYSTEMD || HAVE_ELOGIND
	if (cmd->idlehint) {
		set_idle_hint(true);
	} else
#endif
	if (cmd->idle_cmd) {
		cmd_exec(cmd->idle_cmd);
	}
}

static void handle_resume(void *data, struct org_kde_kwin_idle_timeout *timer) {
	struct swayidle_timeout_cmd *cmd = data;
	swayidle_log(LOG_DEBUG, "active state");
	if (cmd->registered_timeout != cmd->timeout) {
		register_timeout(cmd, cmd->timeout);
	}
#if HAVE_SYSTEMD || HAVE_ELOGIND
	if (cmd->idlehint) {
		set_idle_hint(false);
	} else
#endif
	if (cmd->resume_cmd) {
		cmd_exec(cmd->resume_cmd);
	}
}

static const struct org_kde_kwin_idle_timeout_listener idle_timer_listener = {
	.idle = handle_idle,
	.resumed = handle_resume,
};

static char *parse_command(int argc, char **argv) {
	if (argc < 1) {
		swayidle_log(LOG_ERROR, "Missing command");
		return NULL;
	}

	swayidle_log(LOG_DEBUG, "Command: %s", argv[0]);
	return strdup(argv[0]);
}

static struct swayidle_timeout_cmd *build_timeout_cmd(int argc, char **argv) {
	errno = 0;
	char *endptr;
	int seconds = strtoul(argv[1], &endptr, 10);
	if (errno != 0 || *endptr != '\0') {
		swayidle_log(LOG_ERROR, "Invalid %s parameter '%s', it should be a "
				"numeric value representing seconds", argv[0], argv[1]);
		exit(-1);
	}

	struct swayidle_timeout_cmd *cmd =
		calloc(1, sizeof(struct swayidle_timeout_cmd));
	cmd->idlehint = false;

	if (seconds > 0) {
		cmd->timeout = seconds * 1000;
	} else {
		cmd->timeout = -1;
	}

	return cmd;
}

static int parse_timeout(int argc, char **argv) {
	if (argc < 3) {
		swayidle_log(LOG_ERROR, "Too few parameters to timeout command. "
				"Usage: timeout <seconds> <command>");
		exit(-1);
	}

	struct swayidle_timeout_cmd *cmd = build_timeout_cmd(argc, argv);

	swayidle_log(LOG_DEBUG, "Register idle timeout at %d ms", cmd->timeout);
	swayidle_log(LOG_DEBUG, "Setup idle");
	cmd->idle_cmd = parse_command(argc - 2, &argv[2]);

	int result = 3;
	if (argc >= 5 && !strcmp("resume", argv[3])) {
		swayidle_log(LOG_DEBUG, "Setup resume");
		cmd->resume_cmd = parse_command(argc - 4, &argv[4]);
		result = 5;
	}
	wl_list_insert(&state.timeout_cmds, &cmd->link);
	return result;
}

static int parse_sleep(int argc, char **argv) {
#if !HAVE_SYSTEMD && !HAVE_ELOGIND
	swayidle_log(LOG_ERROR, "%s not supported: swayidle was compiled "
		       "with neither systemd nor elogind support.", "before-sleep");
	exit(-1);
#endif
	if (argc < 2) {
		swayidle_log(LOG_ERROR, "Too few parameters to before-sleep command. "
				"Usage: before-sleep <command>");
		exit(-1);
	}

	state.before_sleep_cmd = parse_command(argc - 1, &argv[1]);
	if (state.before_sleep_cmd) {
		swayidle_log(LOG_DEBUG, "Setup sleep lock: %s", state.before_sleep_cmd);
	}

	return 2;
}

static int parse_resume(int argc, char **argv) {
#if !HAVE_SYSTEMD && !HAVE_ELOGIND
	swayidle_log(LOG_ERROR, "%s not supported: swayidle was compiled "
			"with neither systemd nor elogind support.", "after-resume");
	exit(-1);
#endif
	if (argc < 2) {
		swayidle_log(LOG_ERROR, "Too few parameters to after-resume command. "
				"Usage: after-resume <command>");
		exit(-1);
	}

	state.after_resume_cmd = parse_command(argc - 1, &argv[1]);
	if (state.after_resume_cmd) {
		swayidle_log(LOG_DEBUG, "Setup resume hook: %s", state.after_resume_cmd);
	}

	return 2;
}

static int parse_lock(int argc, char **argv) {
#if !HAVE_SYSTEMD && !HAVE_ELOGIND
	swayidle_log(LOG_ERROR, "%s not supported: swayidle was compiled"
			" with neither systemd nor elogind support.", "lock");
	exit(-1);
#endif
	if (argc < 2) {
		swayidle_log(LOG_ERROR, "Too few parameters to lock command. "
				"Usage: lock <command>");
		exit(-1);
	}

	state.logind_lock_cmd = parse_command(argc - 1, &argv[1]);
	if (state.logind_lock_cmd) {
		swayidle_log(LOG_DEBUG, "Setup lock hook: %s", state.logind_lock_cmd);
	}

	return 2;
}

static int parse_unlock(int argc, char **argv) {
#if !HAVE_SYSTEMD && !HAVE_ELOGIND
	swayidle_log(LOG_ERROR, "%s not supported: swayidle was compiled"
			" with neither systemd nor elogind support.", "unlock");
	exit(-1);
#endif
	if (argc < 2) {
		swayidle_log(LOG_ERROR, "Too few parameters to unlock command. "
				"Usage: unlock <command>");
		exit(-1);
	}

	state.logind_unlock_cmd = parse_command(argc - 1, &argv[1]);
	if (state.logind_unlock_cmd) {
		swayidle_log(LOG_DEBUG, "Setup unlock hook: %s", state.logind_unlock_cmd);
	}

	return 2;
}

static int parse_idlehint(int argc, char **argv) {
#if !HAVE_SYSTEMD && !HAVE_ELOGIND
	swayidle_log(LOG_ERROR, "%s not supported: swayidle was compiled"
			" with neither systemd nor elogind support.", "idlehint");
	exit(-1);
#endif
	if (state.logind_idlehint) {
		swayidle_log(LOG_ERROR, "Cannot add multiple idlehint events");
		exit(-1);
	}
	if (argc < 2) {
		swayidle_log(LOG_ERROR, "Too few parameters to idlehint command. "
				"Usage: idlehint <seconds>");
		exit(-1);
	}

	struct swayidle_timeout_cmd *cmd = build_timeout_cmd(argc, argv);
	cmd->idlehint = true;

	swayidle_log(LOG_DEBUG, "Register idlehint timeout at %d ms", cmd->timeout);
	wl_list_insert(&state.timeout_cmds, &cmd->link);
	state.logind_idlehint = true;
	return 2;
}

static int parse_args(int argc, char *argv[]) {
	int c;
	while ((c = getopt(argc, argv, "hdw")) != -1) {
		switch (c) {
		case 'd':
			verbosity = LOG_DEBUG;
			break;
		case 'w':
			state.wait = true;
			break;
		case 'h':
		case '?':
			printf("Usage: %s [OPTIONS]\n", argv[0]);
			printf("  -h\tthis help menu\n");
			printf("  -d\tdebug\n");
			printf("  -w\twait for command to finish\n");
			return 1;
		default:
			return 1;
		}
	}

	wl_list_init(&state.timeout_cmds);

	int i = optind;
	while (i < argc) {
		if (!strcmp("timeout", argv[i])) {
			swayidle_log(LOG_DEBUG, "Got timeout");
			i += parse_timeout(argc - i, &argv[i]);
		} else if (!strcmp("before-sleep", argv[i])) {
			swayidle_log(LOG_DEBUG, "Got before-sleep");
			i += parse_sleep(argc - i, &argv[i]);
		} else if (!strcmp("after-resume", argv[i])) {
			swayidle_log(LOG_DEBUG, "Got after-resume");
			i += parse_resume(argc - i, &argv[i]);
		} else if (!strcmp("lock", argv[i])) {
			swayidle_log(LOG_DEBUG, "Got lock");
			i += parse_lock(argc - i, &argv[i]);
		} else if (!strcmp("unlock", argv[i])) {
			swayidle_log(LOG_DEBUG, "Got unlock");
			i += parse_unlock(argc - i, &argv[i]);
		} else if (!strcmp("idlehint", argv[i])) {
			swayidle_log(LOG_DEBUG, "Got idlehint");
			i += parse_idlehint(argc - i, &argv[i]);
		} else {
			swayidle_log(LOG_ERROR, "Unsupported command '%s'", argv[i]);
			return 1;
		}
	}

	return 0;
}

static int handle_signal(int sig, void *data) {
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		sway_terminate(0);
		return 0;
	case SIGUSR1:
		swayidle_log(LOG_DEBUG, "Got SIGUSR1");
		struct swayidle_timeout_cmd *cmd;
		wl_list_for_each(cmd, &state.timeout_cmds, link) {
			register_timeout(cmd, 0);
		}
		return 1;
	}
	assert(false); // not reached
}

static int display_event(int fd, uint32_t mask, void *data) {
	if ((mask & WL_EVENT_HANGUP) || (mask & WL_EVENT_ERROR)) {
		sway_terminate(0);
	}

	int count = 0;
	if (mask & WL_EVENT_READABLE) {
		count = wl_display_dispatch(state.display);
	}
	if (mask & WL_EVENT_WRITABLE) {
		wl_display_flush(state.display);
	}
	if (mask == 0) {
		count = wl_display_dispatch_pending(state.display);
		wl_display_flush(state.display);
	}

	if (count < 0) {
		swayidle_log_errno(LOG_ERROR, "wl_display_dispatch failed, exiting");
		sway_terminate(0);
	}

	return count;
}

int main(int argc, char *argv[]) {
	if (parse_args(argc, argv) != 0) {
		return -1;
	}

	state.event_loop = wl_event_loop_create();

	wl_event_loop_add_signal(state.event_loop, SIGINT, handle_signal, NULL);
	wl_event_loop_add_signal(state.event_loop, SIGTERM, handle_signal, NULL);
	wl_event_loop_add_signal(state.event_loop, SIGUSR1, handle_signal, NULL);

	state.display = wl_display_connect(NULL);
	if (state.display == NULL) {
		swayidle_log(LOG_ERROR, "Unable to connect to the compositor. "
				"If your compositor is running, check or set the "
				"WAYLAND_DISPLAY environment variable.");
		return -3;
	}

	struct wl_registry *registry = wl_display_get_registry(state.display);
	wl_registry_add_listener(registry, &registry_listener, NULL);
	wl_display_roundtrip(state.display);

	if (idle_manager == NULL) {
		swayidle_log(LOG_ERROR, "Display doesn't support idle protocol");
		return -4;
	}
	if (seat == NULL) {
		swayidle_log(LOG_ERROR, "Seat error");
		return -5;
	}

	bool should_run = !wl_list_empty(&state.timeout_cmds);
#if HAVE_SYSTEMD || HAVE_ELOGIND
	connect_to_bus();
	if (state.before_sleep_cmd || state.after_resume_cmd) {
		should_run = true;
		setup_sleep_listener();
	}
	if (state.logind_lock_cmd) {
		should_run = true;
		setup_lock_listener();
	}
	if (state.logind_unlock_cmd) {
		should_run = true;
		setup_unlock_listener();
	}
	if (state.logind_idlehint) {
		set_idle_hint(false);
	}
#endif
	if (!should_run) {
		swayidle_log(LOG_INFO, "No command specified! Nothing to do, will exit");
		sway_terminate(0);
	}

	struct swayidle_timeout_cmd *cmd;
	wl_list_for_each(cmd, &state.timeout_cmds, link) {
		register_timeout(cmd, cmd->timeout);
	}

	wl_display_roundtrip(state.display);

	struct wl_event_source *source = wl_event_loop_add_fd(state.event_loop,
		wl_display_get_fd(state.display), WL_EVENT_READABLE,
		display_event, NULL);
	wl_event_source_check(source);

	while (wl_event_loop_dispatch(state.event_loop, -1) != 1) {
		// This space intentionally left blank
	}

	sway_terminate(0);
}
