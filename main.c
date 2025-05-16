#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <wayland-client-protocol.h>
#include <wayland-client.h>
#include <wayland-server.h>
#include <wayland-util.h>
#include <wordexp.h>
#include "config.h"
#include "ext-idle-notify-v1-client-protocol.h"
#include "log.h"
#if HAVE_SYSTEMD
#include <systemd/sd-bus.h>
#include <systemd/sd-login.h>
#elif HAVE_ELOGIND
#include <elogind/sd-bus.h>
#include <elogind/sd-login.h>
#endif

static struct ext_idle_notifier_v1 *idle_notifier = NULL;
static struct wl_seat *seat = NULL;

struct swayidle_state {
	struct wl_display *display;
	struct wl_event_loop *event_loop;
	struct wl_list timeout_cmds; // struct swayidle_timeout_cmd *
	struct wl_list seats;
	char *seat_name;
	char *before_sleep_cmd;
	char *after_resume_cmd;
	char *logind_lock_cmd;
	char *logind_unlock_cmd;
	bool logind_idlehint;
	bool timeouts_enabled;
	bool wait;
} state;

struct swayidle_timeout_cmd {
	struct wl_list link;
	int timeout, registered_timeout;
	struct ext_idle_notification_v1 *idle_notification;
	char *idle_cmd;
	char *resume_cmd;
	bool idlehint;
	bool resume_pending;
};

struct seat {
	struct wl_list link;
	struct wl_seat *proxy;

	char *name;
	uint32_t capabilities;
};

static const char *verbosity_colors[] = {
	[LOG_SILENT] = "",
	[LOG_ERROR ] = "\x1B[1;31m",
	[LOG_INFO  ] = "\x1B[1;34m",
	[LOG_DEBUG ] = "\x1B[1;30m",
};

static enum log_importance log_importance = LOG_INFO;

void swayidle_log_init(enum log_importance verbosity) {
	if (verbosity < LOG_IMPORTANCE_LAST) {
		log_importance = verbosity;
	}
}

void _swayidle_log(enum log_importance verbosity, const char *fmt, ...) {
	if (verbosity > log_importance) {
		return;
	}

	va_list args;
	va_start(args, fmt);

	// prefix the time to the log message
	struct tm result;
	time_t t = time(NULL);
	struct tm *tm_info = localtime_r(&t, &result);
	char buffer[26];

	// generate time prefix
	strftime(buffer, sizeof(buffer), "%F %T - ", tm_info);
	fprintf(stderr, "%s", buffer);

	unsigned c = (verbosity < LOG_IMPORTANCE_LAST)
		? verbosity : LOG_IMPORTANCE_LAST - 1;

	if (isatty(STDERR_FILENO)) {
		fprintf(stderr, "%s", verbosity_colors[c]);
	}

	vfprintf(stderr, fmt, args);

	if (isatty(STDERR_FILENO)) {
		fprintf(stderr, "\x1B[0m");
	}
	fprintf(stderr, "\n");

	va_end(args);
}

static void swayidle_init() {
	memset(&state, 0, sizeof(state));
	wl_list_init(&state.timeout_cmds);
	wl_list_init(&state.seats);
}

static void swayidle_finish() {

	struct swayidle_timeout_cmd *cmd;
	struct swayidle_timeout_cmd *tmp;
	wl_list_for_each_safe(cmd, tmp, &state.timeout_cmds, link) {
		wl_list_remove(&cmd->link);
		free(cmd->idle_cmd);
		free(cmd->resume_cmd);
		free(cmd);
	}

	free(state.after_resume_cmd);
	free(state.before_sleep_cmd);
}

void sway_terminate(int exit_code) {
	wl_display_disconnect(state.display);
	wl_event_loop_destroy(state.event_loop);
	swayidle_finish();
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
			sigset_t set;
			sigemptyset(&set);
			sigprocmask(SIG_SETMASK, &set, NULL);
			signal(SIGINT, SIG_DFL);
			signal(SIGTERM, SIG_DFL);
			signal(SIGUSR1, SIG_DFL);

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
		if (state.wait) {
			swayidle_log(LOG_DEBUG, "Blocking until process exits");
		}
		int status = 0;
		waitpid(pid, &status, 0);
		if (state.wait && WIFEXITED(status)) {
			swayidle_log(LOG_DEBUG, "Process exit status: %d", WEXITSTATUS(status));
		}
	}
}

#if HAVE_SYSTEMD || HAVE_ELOGIND
#define DBUS_LOGIND_SERVICE "org.freedesktop.login1"
#define DBUS_LOGIND_PATH "/org/freedesktop/login1"
#define DBUS_LOGIND_MANAGER_INTERFACE "org.freedesktop.login1.Manager"
#define DBUS_LOGIND_SESSION_INTERFACE "org.freedesktop.login1.Session"

static void enable_timeouts(void);
static void disable_timeouts(void);

static int sleep_lock_fd = -1;
static struct sd_bus *bus = NULL;
static char *session_name = NULL;

static void acquire_inhibitor_lock(const char *type, const char *mode,
	int *fd) {
	sd_bus_message *msg = NULL;
	sd_bus_error error = SD_BUS_ERROR_NULL;
	char why[35];

	sprintf(why, "Swayidle is preventing %s", type);
	int ret = sd_bus_call_method(bus, DBUS_LOGIND_SERVICE, DBUS_LOGIND_PATH,
			DBUS_LOGIND_MANAGER_INTERFACE, "Inhibit", &error, &msg,
			"ssss", type, "swayidle", why, mode);
	if (ret < 0) {
		swayidle_log(LOG_ERROR,
				"Failed to send %s inhibit signal: %s", type, error.message);
		goto cleanup;
	}

	ret = sd_bus_message_read(msg, "h", fd);
	if (ret < 0) {
		errno = -ret;
		swayidle_log_errno(LOG_ERROR,
				"Failed to parse D-Bus response for %s inhibit", type);
		goto cleanup;
	}

	*fd = fcntl(*fd, F_DUPFD_CLOEXEC, 3);
	if (*fd >= 0) {
		swayidle_log(LOG_DEBUG, "Got %s lock: %d", type, *fd);
	} else {
		swayidle_log_errno(LOG_ERROR, "Failed to copy %s lock fd", type);
	}

cleanup:
	sd_bus_error_free(&error);
	sd_bus_message_unref(msg);
}

static void release_inhibitor_lock(int fd) {
	if (fd >= 0) {
		swayidle_log(LOG_DEBUG, "Releasing inhibitor lock %d", fd);
		close(fd);
	}
}

static void set_idle_hint(bool hint) {
	swayidle_log(LOG_DEBUG, "SetIdleHint %d", hint);
	sd_bus_message *msg = NULL;
	sd_bus_error error = SD_BUS_ERROR_NULL;
	int ret = sd_bus_call_method(bus, DBUS_LOGIND_SERVICE,
			session_name, DBUS_LOGIND_SESSION_INTERFACE, "SetIdleHint",
			&error, &msg, "b", hint);
	if (ret < 0) {
		swayidle_log(LOG_ERROR,
				"Failed to send SetIdleHint signal: %s", error.message);
	}

	sd_bus_error_free(&error);
	sd_bus_message_unref(msg);
}

static bool get_logind_idle_inhibit(void) {
	const char *locks;
	bool res;

	sd_bus_message *reply = NULL;

	int ret = sd_bus_get_property(bus, DBUS_LOGIND_SERVICE, DBUS_LOGIND_PATH,
			DBUS_LOGIND_MANAGER_INTERFACE, "BlockInhibited", NULL, &reply, "s");
	if (ret < 0) {
		goto error;
	}

	ret = sd_bus_message_read_basic(reply, 's', &locks);
	if (ret < 0) {
		goto error;
	}

	res = strstr(locks, "idle") != NULL;
	sd_bus_message_unref(reply);

	return res;

error:
	sd_bus_message_unref(reply);
	errno = -ret;
	swayidle_log_errno(LOG_ERROR,
				"Failed to parse get BlockInhibited property");
	return false;
}

static int prepare_for_sleep(sd_bus_message *msg, void *userdata,
		sd_bus_error *ret_error) {
	/* "b" apparently reads into an int, not a bool */
	int going_down = 1;
	int ret = sd_bus_message_read(msg, "b", &going_down);
	if (ret < 0) {
		errno = -ret;
		swayidle_log_errno(LOG_ERROR,
				"Failed to parse D-Bus response for Inhibit");
	}
	swayidle_log(LOG_DEBUG, "PrepareForSleep signal received %d", going_down);
	if (!going_down) {
		acquire_inhibitor_lock("sleep", "delay", &sleep_lock_fd);
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

	release_inhibitor_lock(sleep_lock_fd);
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

static int handle_property_changed(sd_bus_message *msg, void *userdata,
		sd_bus_error *ret_error) {
	const char *name;
	swayidle_log(LOG_DEBUG, "PropertiesChanged signal received");

	int ret = sd_bus_message_read_basic(msg, 's', &name);
	if (ret < 0) {
		goto error;
	}

	if (!strcmp(name, DBUS_LOGIND_MANAGER_INTERFACE)) {
		swayidle_log(LOG_DEBUG, "Got PropertyChanged: %s", name);
		ret = sd_bus_message_enter_container(msg, 'a', "{sv}");
		if (ret < 0) {
			goto error;
		}

		const char *prop;
		while ((ret = sd_bus_message_enter_container(msg, 'e', "sv")) > 0) {
			ret = sd_bus_message_read_basic(msg, 's', &prop);
			if (ret < 0) {
				goto error;
			}

			if (!strcmp(prop, "BlockInhibited")) {
				if (get_logind_idle_inhibit()) {
					swayidle_log(LOG_DEBUG, "Logind idle inhibitor found");
					disable_timeouts();
				} else {
					swayidle_log(LOG_DEBUG, "Logind idle inhibitor not found");
					enable_timeouts();
				}
				return 0;
			} else {
				ret = sd_bus_message_skip(msg, "v");
				if (ret < 0) {
					goto error;
				}
			}

			ret = sd_bus_message_exit_container(msg);
			if (ret < 0) {
				goto error;
			}
		}
	}

	if (ret < 0) {
		goto error;
	}

	return 0;

error:
	errno = -ret;
	swayidle_log_errno(LOG_ERROR,
				"Failed to parse D-Bus response for PropertyChanged");
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

static void set_session(void) {
	sd_bus_message *msg = NULL;
	sd_bus_error error = SD_BUS_ERROR_NULL;
	const char *session_name_tmp;

	int ret = sd_bus_call_method(bus, DBUS_LOGIND_SERVICE, DBUS_LOGIND_PATH,
			DBUS_LOGIND_MANAGER_INTERFACE, "GetSession",
			&error, &msg, "s", "auto");
	if (ret < 0) {
		swayidle_log(LOG_DEBUG,
				"GetSession failed: %s", error.message);
		sd_bus_error_free(&error);
		sd_bus_message_unref(msg);

		ret = sd_bus_call_method(bus, DBUS_LOGIND_SERVICE, DBUS_LOGIND_PATH,
				DBUS_LOGIND_MANAGER_INTERFACE, "GetSessionByPID",
				&error, &msg, "u", getpid());
		if (ret < 0) {
			swayidle_log(LOG_DEBUG,
					"GetSessionByPID failed: %s", error.message);
			swayidle_log(LOG_ERROR,
					"Failed to find session");
			goto cleanup;
		}
	}

	ret = sd_bus_message_read(msg, "o", &session_name_tmp);
	if (ret < 0) {
		swayidle_log(LOG_ERROR,
				"Failed to read session name");
		goto cleanup;
	}
	session_name = strdup(session_name_tmp);
	swayidle_log(LOG_DEBUG, "Using session: %s", session_name);

cleanup:
	sd_bus_error_free(&error);
	sd_bus_message_unref(msg);
}

static void connect_to_bus(void) {
	int ret = sd_bus_default_system(&bus);
	if (ret < 0) {
		errno = -ret;
		swayidle_log_errno(LOG_ERROR, "Failed to open D-Bus connection");
		return;
	}
	struct wl_event_source *source = wl_event_loop_add_fd(state.event_loop,
		sd_bus_get_fd(bus), WL_EVENT_READABLE, dbus_event, bus);
	wl_event_source_check(source);
	set_session();
}

static void setup_sleep_listener(void) {
	int ret = sd_bus_match_signal(bus, NULL, DBUS_LOGIND_SERVICE,
                DBUS_LOGIND_PATH, DBUS_LOGIND_MANAGER_INTERFACE,
                "PrepareForSleep", prepare_for_sleep, NULL);
	if (ret < 0) {
		errno = -ret;
		swayidle_log_errno(LOG_ERROR, "Failed to add D-Bus signal match : sleep");
		return;
	}
	acquire_inhibitor_lock("sleep", "delay", &sleep_lock_fd);
}

static void setup_lock_listener(void) {
	int ret = sd_bus_match_signal(bus, NULL, DBUS_LOGIND_SERVICE,
                session_name, DBUS_LOGIND_SESSION_INTERFACE,
                "Lock", handle_lock, NULL);
	if (ret < 0) {
		errno = -ret;
		swayidle_log_errno(LOG_ERROR, "Failed to add D-Bus signal match : lock");
		return;
	}
}

static void setup_unlock_listener(void) {
	int ret = sd_bus_match_signal(bus, NULL, DBUS_LOGIND_SERVICE,
                session_name, DBUS_LOGIND_SESSION_INTERFACE,
                "Unlock", handle_unlock, NULL);
	if (ret < 0) {
		errno = -ret;
		swayidle_log_errno(LOG_ERROR, "Failed to add D-Bus signal match : unlock");
		return;
	}
}

static void setup_property_changed_listener(void) {
	int ret = sd_bus_match_signal(bus, NULL, NULL,
                DBUS_LOGIND_PATH, "org.freedesktop.DBus.Properties",
                "PropertiesChanged", handle_property_changed, NULL);
	if (ret < 0) {
		errno = -ret;
		swayidle_log_errno(LOG_ERROR, "Failed to add D-Bus signal match : property changed");
		return;
	}
}
#endif

static void seat_handle_capabilities(void *data, struct wl_seat *seat,
		uint32_t capabilities) {
	struct seat *self = data;
	self->capabilities = capabilities;
}

static void seat_handle_name(void *data, struct wl_seat *seat,
		const char *name) {
	struct seat *self = data;
	self->name = strdup(name);
}

static const struct wl_seat_listener wl_seat_listener = {
	.name = seat_handle_name,
	.capabilities = seat_handle_capabilities,
};

static void handle_global(void *data, struct wl_registry *registry,
		uint32_t name, const char *interface, uint32_t version) {
	if (strcmp(interface, ext_idle_notifier_v1_interface.name) == 0) {
		idle_notifier =
			wl_registry_bind(registry, name, &ext_idle_notifier_v1_interface, 1);
	} else if (strcmp(interface, wl_seat_interface.name) == 0) {
		struct seat *s = calloc(1, sizeof(struct seat));
		s->proxy = wl_registry_bind(registry, name, &wl_seat_interface, 2);

		wl_seat_add_listener(s->proxy, &wl_seat_listener, s);
		wl_list_insert(&state.seats, &s->link);
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

static const struct ext_idle_notification_v1_listener idle_notification_listener;

static void destroy_cmd_timer(struct swayidle_timeout_cmd *cmd) {
	if (cmd->idle_notification != NULL) {
		ext_idle_notification_v1_destroy(cmd->idle_notification);
		cmd->idle_notification = NULL;
	}
}

static void register_timeout(struct swayidle_timeout_cmd *cmd,
		int timeout, bool obey_inhibitors) {
	destroy_cmd_timer(cmd);

	if (timeout < 0) {
		swayidle_log(LOG_DEBUG, "Not registering idle timeout");
		return;
	}
	swayidle_log(LOG_DEBUG, "Register with timeout: %d", timeout);
	uint32_t version = ext_idle_notifier_v1_get_version(idle_notifier);
	if (obey_inhibitors || version < EXT_IDLE_NOTIFIER_V1_GET_INPUT_IDLE_NOTIFICATION_SINCE_VERSION) {
		cmd->idle_notification = ext_idle_notifier_v1_get_idle_notification(
			idle_notifier, timeout, seat);
	} else {
		cmd->idle_notification = ext_idle_notifier_v1_get_input_idle_notification(
			idle_notifier, timeout, seat);
	}
	ext_idle_notification_v1_add_listener(cmd->idle_notification,
		&idle_notification_listener, cmd);
	cmd->registered_timeout = timeout;
}

static void enable_timeouts(void) {
	if (state.timeouts_enabled) {
		return;
	}
#if HAVE_SYSTEMD || HAVE_ELOGIND
	if (get_logind_idle_inhibit()) {
		swayidle_log(LOG_INFO, "Not enabling timeouts: idle inhibitor found");
		return;
	}
#endif
	swayidle_log(LOG_DEBUG, "Enable idle timeouts");

	state.timeouts_enabled = true;
	struct swayidle_timeout_cmd *cmd;
	wl_list_for_each(cmd, &state.timeout_cmds, link) {
		register_timeout(cmd, cmd->timeout, true);
	}
}

#if HAVE_SYSTEMD || HAVE_ELOGIND
static void disable_timeouts(void) {
	if (!state.timeouts_enabled) {
		return;
	}
	swayidle_log(LOG_DEBUG, "Disable idle timeouts");

	state.timeouts_enabled = false;
	struct swayidle_timeout_cmd *cmd;
	wl_list_for_each(cmd, &state.timeout_cmds, link) {
		destroy_cmd_timer(cmd);
	}
	if (state.logind_idlehint) {
		set_idle_hint(false);
	}
}
#endif

static void handle_idled(void *data, struct ext_idle_notification_v1 *notif) {
	struct swayidle_timeout_cmd *cmd = data;
	cmd->resume_pending = true;
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

static void handle_resumed(void *data, struct ext_idle_notification_v1 *notif) {
	struct swayidle_timeout_cmd *cmd = data;
	cmd->resume_pending = false;
	swayidle_log(LOG_DEBUG, "active state");
	if (cmd->registered_timeout != cmd->timeout) {
		register_timeout(cmd, cmd->timeout, true);
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

static const struct ext_idle_notification_v1_listener idle_notification_listener = {
	.idled = handle_idled,
	.resumed = handle_resumed,
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
	cmd->resume_pending = false;

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

static int parse_args(int argc, char *argv[], char **config_path) {
	int c;
	while ((c = getopt(argc, argv, "C:hdwS:")) != -1) {
		switch (c) {
		case 'C':
			free(*config_path);
			*config_path = strdup(optarg);
			break;
		case 'd':
			swayidle_log_init(LOG_DEBUG);
			break;
		case 'w':
			state.wait = true;
			break;
		case 'S':
			state.seat_name = strdup(optarg);
			break;
		case 'h':
		case '?':
			printf("Usage: %s [OPTIONS]\n", argv[0]);
			printf("  -h\tthis help menu\n");
			printf("  -C\tpath to config file\n");
			printf("  -d\tdebug\n");
			printf("  -w\twait for command to finish\n");
			printf("  -S\tpick the seat to work with\n");
			return 1;
		default:
			return 1;
		}
	}

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
	struct swayidle_timeout_cmd *cmd;
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		swayidle_log(LOG_DEBUG, "Got SIGTERM");
		wl_list_for_each(cmd, &state.timeout_cmds, link) {
			if (cmd->resume_pending) {
				handle_resumed(cmd, NULL);
			}
		}
		sway_terminate(0);
		return 0;
	case SIGUSR1:
		swayidle_log(LOG_DEBUG, "Got SIGUSR1");
		wl_list_for_each(cmd, &state.timeout_cmds, link) {
			register_timeout(cmd, 0, false);
		}
		return 1;
	}
	abort(); // not reached
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

static char *get_config_path(void) {
	static char *config_paths[3] = {
		"$XDG_CONFIG_HOME/swayidle/config",
		"$HOME/.swayidle/config",
		SYSCONFDIR "/swayidle/config",
	};

	char *config_home = getenv("XDG_CONFIG_HOME");

	if (!config_home || config_home[0] == '\n') {
		config_paths[0] = "$HOME/.config/swayidle/config";
	}

	wordexp_t p;
	char *path;
	for (size_t i = 0; i < sizeof(config_paths) / sizeof(char *); ++i) {
		if (wordexp(config_paths[i], &p, 0) == 0) {
			path = strdup(p.we_wordv[0]);
			wordfree(&p);
			if (path && access(path, R_OK) == 0) {
				return path;
			}
			free(path);
		}
	}

	return NULL;
}

static const char *wordexp_strerror(int err) {
	switch (err) {
		case WRDE_BADCHAR: return "illegal character";
		case WRDE_BADVAL:  return "undefined shell variable";
		case WRDE_CMDSUB:  return "command substitutions are forbidden";
		case WRDE_NOSPACE: return "out of memory";
		case WRDE_SYNTAX:  return "syntax error";
		default:           return "unknown error";
	}
}

static int load_config(const char *config_path) {
	FILE *f = fopen(config_path, "r");
	if (!f) {
		return -ENOENT;
	}

	int we_err = 0;
	size_t lineno = 0;
	char *line = NULL;
	size_t n = 0;
	ssize_t nread;
	while ((nread = getline(&line, &n, f)) != -1) {
		lineno++;
		if (line[nread-1] == '\n') {
			line[nread-1] = '\0';
		}

		if (strlen(line) == 0 || line[0] == '#') {
			continue;
		}

		size_t i = 0;
		while (line[i] != '\0' && line[i] != ' ') {
			i++;
		}

		wordexp_t p;
		if ((we_err = wordexp(line, &p, 0)) != 0) {
			swayidle_log(LOG_ERROR, "Shell expansion error on line %zu: %s (%d)", lineno, wordexp_strerror(we_err), we_err);
			free(line);
			return -EINVAL;
		}

		if (strncmp("timeout", line, i) == 0) {
			parse_timeout(p.we_wordc, p.we_wordv);
		} else if (strncmp("before-sleep", line, i) == 0) {
			parse_sleep(p.we_wordc, p.we_wordv);
		} else if (strncmp("after-resume", line, i) == 0) {
			parse_resume(p.we_wordc, p.we_wordv);
		} else if (strncmp("lock", line, i) == 0) {
			parse_lock(p.we_wordc, p.we_wordv);
		} else if (strncmp("unlock", line, i) == 0) {
			parse_unlock(p.we_wordc, p.we_wordv);
		} else if (strncmp("idlehint", line, i) == 0) {
			parse_idlehint(p.we_wordc, p.we_wordv);
		} else {
			line[i] = 0;
			swayidle_log(LOG_ERROR, "Unexpected keyword \"%s\" in line %zu", line, lineno);
			free(line);
			return -EINVAL;
		}
		wordfree(&p);
	}
	free(line);
	fclose(f);

	return 0;
}


int main(int argc, char *argv[]) {
	swayidle_init();
	char *config_path = NULL;
	if (parse_args(argc, argv, &config_path) != 0) {
		swayidle_finish();
		free(config_path);
		return -1;
	}

	if (!config_path) {
		config_path = get_config_path();
	}

	int config_load = -ENOENT;
	if (config_path) {
		config_load = load_config(config_path);
	}
	if (config_load == -ENOENT) {
		swayidle_log(LOG_DEBUG, "No config file found.");
	} else if (config_load == -EINVAL) {
		swayidle_log(LOG_ERROR, "Config file %s has errors, exiting.", config_path);
		exit(-1);
	} else {
		swayidle_log(LOG_DEBUG, "Loaded config at %s", config_path);
	}

	free(config_path);

	state.event_loop = wl_event_loop_create();

	wl_event_loop_add_signal(state.event_loop, SIGINT, handle_signal, NULL);
	wl_event_loop_add_signal(state.event_loop, SIGTERM, handle_signal, NULL);
	wl_event_loop_add_signal(state.event_loop, SIGUSR1, handle_signal, NULL);

	state.display = wl_display_connect(NULL);
	if (state.display == NULL) {
		swayidle_log(LOG_ERROR, "Unable to connect to the compositor. "
				"If your compositor is running, check or set the "
				"WAYLAND_DISPLAY environment variable.");
		swayidle_finish();
		return -3;
	}

	struct wl_registry *registry = wl_display_get_registry(state.display);
	wl_registry_add_listener(registry, &registry_listener, NULL);
	wl_display_roundtrip(state.display);
	wl_display_roundtrip(state.display);

	struct seat *seat_i;
	wl_list_for_each(seat_i, &state.seats, link) {
		if (state.seat_name == NULL || strcmp(seat_i->name, state.seat_name) == 0) {
			seat = seat_i->proxy;
		}
	}

	if (idle_notifier == NULL) {
		swayidle_log(LOG_ERROR, "Compositor doesn't support idle protocol");
		swayidle_finish();
		return -4;
	}
	if (seat == NULL) {
		if (state.seat_name != NULL) {
			swayidle_log(LOG_ERROR, "Seat %s not found", state.seat_name);
		} else {
			swayidle_log(LOG_ERROR, "No seat found");
		}
		swayidle_finish();
		return -5;
	}

	bool should_run = !wl_list_empty(&state.timeout_cmds);
#if HAVE_SYSTEMD || HAVE_ELOGIND
	bool need_logind = state.before_sleep_cmd || state.after_resume_cmd ||
		state.logind_lock_cmd || state.logind_unlock_cmd ||
		state.logind_idlehint;
	if (need_logind) {
		connect_to_bus();
		setup_property_changed_listener();
	}
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

	enable_timeouts();
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
