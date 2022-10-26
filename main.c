#define _POSIX_C_SOURCE 200809L
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
#include "idle-client-protocol.h"
#include "ext-idle-notify-v1-client-protocol.h"
#include "log.h"

static struct org_kde_kwin_idle *kde_idle_manager = NULL;
static struct ext_idle_notifier_v1 *idle_notifier = NULL;
static struct wl_seat *seat = NULL;

struct swayidle_state {
	struct wl_display *display;
	struct wl_event_loop *event_loop;
	struct wl_list timeout_cmds; // struct swayidle_timeout_cmd *
	struct wl_list seats;
	char *seat_name;
	bool timeouts_enabled;
	bool wait;
} state;

struct swayidle_timeout_cmd {
	struct wl_list link;
	int timeout, registered_timeout;
	struct org_kde_kwin_idle_timeout *kde_idle_timer;
	struct ext_idle_notification_v1 *idle_notification;
	char *idle_cmd;
	char *resume_cmd;
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
	if (strcmp(interface, org_kde_kwin_idle_interface.name) == 0) {
		kde_idle_manager =
			wl_registry_bind(registry, name, &org_kde_kwin_idle_interface, 1);
	} else if (strcmp(interface, ext_idle_notifier_v1_interface.name) == 0) {
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

static const struct org_kde_kwin_idle_timeout_listener kde_idle_timer_listener;
static const struct ext_idle_notification_v1_listener idle_notification_listener;

static void destroy_cmd_timer(struct swayidle_timeout_cmd *cmd) {
	if (cmd->kde_idle_timer != NULL) {
		swayidle_log(LOG_DEBUG, "Release idle timer");
		org_kde_kwin_idle_timeout_release(cmd->kde_idle_timer);
		cmd->kde_idle_timer = NULL;
	}
	if (cmd->idle_notification != NULL) {
		ext_idle_notification_v1_destroy(cmd->idle_notification);
		cmd->idle_notification = NULL;
	}
}

static void register_timeout(struct swayidle_timeout_cmd *cmd,
		int timeout) {
	destroy_cmd_timer(cmd);

	if (timeout < 0) {
		swayidle_log(LOG_DEBUG, "Not registering idle timeout");
		return;
	}
	swayidle_log(LOG_DEBUG, "Register with timeout: %d", timeout);
	if (idle_notifier != NULL) {
		cmd->idle_notification =
			ext_idle_notifier_v1_get_idle_notification(idle_notifier, timeout, seat);
		ext_idle_notification_v1_add_listener(cmd->idle_notification,
			&idle_notification_listener, cmd);
	} else {
		cmd->kde_idle_timer =
			org_kde_kwin_idle_get_idle_timeout(kde_idle_manager, seat, timeout);
		org_kde_kwin_idle_timeout_add_listener(cmd->kde_idle_timer,
			&kde_idle_timer_listener, cmd);
	}
	cmd->registered_timeout = timeout;
}

static void enable_timeouts(void) {
	if (state.timeouts_enabled) {
		return;
	}
	swayidle_log(LOG_DEBUG, "Enable idle timeouts");

	state.timeouts_enabled = true;
	struct swayidle_timeout_cmd *cmd;
	wl_list_for_each(cmd, &state.timeout_cmds, link) {
		register_timeout(cmd, cmd->timeout);
	}
}

static void handle_idled(struct swayidle_timeout_cmd *cmd) {
	cmd->resume_pending = true;
	swayidle_log(LOG_DEBUG, "idle state");
	if (cmd->idle_cmd) {
		cmd_exec(cmd->idle_cmd);
	}
}

static void handle_resumed(struct swayidle_timeout_cmd *cmd) {
	cmd->resume_pending = false;
	swayidle_log(LOG_DEBUG, "active state");
	if (cmd->registered_timeout != cmd->timeout) {
		register_timeout(cmd, cmd->timeout);
	}
	if (cmd->resume_cmd) {
		cmd_exec(cmd->resume_cmd);
	}
}

static void kde_handle_idle(void *data, struct org_kde_kwin_idle_timeout *timer) {
	struct swayidle_timeout_cmd *cmd = data;
	handle_idled(cmd);
}

static void kde_handle_resumed(void *data, struct org_kde_kwin_idle_timeout *timer) {
	struct swayidle_timeout_cmd *cmd = data;
	handle_resumed(cmd);
}

static const struct org_kde_kwin_idle_timeout_listener kde_idle_timer_listener = {
	.idle = kde_handle_idle,
	.resumed = kde_handle_resumed,
};

static void ext_handle_idled(void *data, struct ext_idle_notification_v1 *notif) {
	struct swayidle_timeout_cmd *cmd = data;
	handle_idled(cmd);
}

static void ext_handle_resumed(void *data, struct ext_idle_notification_v1 *notif) {
	struct swayidle_timeout_cmd *cmd = data;
	handle_resumed(cmd);
}

static const struct ext_idle_notification_v1_listener idle_notification_listener = {
	.idled = ext_handle_idled,
	.resumed = ext_handle_resumed,
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
				handle_resumed(cmd);
			}
		}
		sway_terminate(0);
		return 0;
	case SIGUSR1:
		swayidle_log(LOG_DEBUG, "Got SIGUSR1");
		wl_list_for_each(cmd, &state.timeout_cmds, link) {
			register_timeout(cmd, 0);
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

static int load_config(const char *config_path) {
	FILE *f = fopen(config_path, "r");
	if (!f) {
		return -ENOENT;
	}

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
		wordexp(line, &p, 0);
		if (strncmp("timeout", line, i) == 0) {
			parse_timeout(p.we_wordc, p.we_wordv);
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

	if (kde_idle_manager == NULL && idle_notifier == NULL) {
		swayidle_log(LOG_ERROR, "Display doesn't support idle protocol");
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
