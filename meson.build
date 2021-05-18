project(
	'swayidle',
	'c',
	version: '1.7',
	license: 'MIT',
	meson_version: '>=0.50.0',
	default_options: [
		'c_std=c11',
		'warning_level=2',
		'werror=true',
	],
)

add_project_arguments(
	[
		'-Wno-unused-parameter',
		'-Wno-unused-result',
		'-Wundef',
		'-Wvla',
	],
	language: 'c',
)

sysconfdir = get_option('sysconfdir')
prefix = get_option('prefix')
add_project_arguments(
	'-DSYSCONFDIR="@0@"'.format(join_paths(prefix, sysconfdir)),
	language : 'c')

wayland_client = dependency('wayland-client')
wayland_protos = dependency('wayland-protocols', version: '>=1.14')
wayland_server = dependency('wayland-server')
bash_comp      = dependency('bash-completion', required: false)
fish_comp      = dependency('fish', required: false)

scdoc = find_program('scdoc', required: get_option('man-pages'))
wayland_scanner = find_program('wayland-scanner')

wl_protocol_dir = wayland_protos.get_pkgconfig_variable('pkgdatadir')

if wayland_server.version().version_compare('>=1.14.91')
	code_type = 'private-code'
else
	code_type = 'code'
endif

wayland_scanner_code = generator(
	wayland_scanner,
	output: '@BASENAME@-protocol.c',
	arguments: [code_type, '@INPUT@', '@OUTPUT@'],
)

wayland_scanner_client = generator(
	wayland_scanner,
	output: '@BASENAME@-client-protocol.h',
	arguments: ['client-header', '@INPUT@', '@OUTPUT@'],
)

client_protos_src = wayland_scanner_code.process('idle.xml')
client_protos_headers = wayland_scanner_client.process('idle.xml')

lib_client_protos = static_library(
	'client_protos',
	[client_protos_src, client_protos_headers],
	dependencies: [wayland_client]
) # for the include directory

client_protos = declare_dependency(
	link_with: lib_client_protos,
	sources: client_protos_headers,
)

swayidle_deps = [
	client_protos,
	wayland_client,
	wayland_server,
]

if get_option('sd-bus-provider') == 'auto'
	if not get_option('logind').disabled()
		assert(get_option('auto_features').auto(), 'sd-bus-provider must not be set to auto since auto_features != auto')
	endif
	sdbus = dependency('libsystemd',
		required: false,
		not_found_message: 'libsystemd not found, trying libelogind',
	)
	if not sdbus.found()
		sdbus = dependency('libelogind',
			required: false,
			not_found_message: 'libelogind not found, trying basu',
		)
	endif
	if not sdbus.found()
		sdbus = dependency('basu', required: false)
	endif
else
	sdbus = dependency(get_option('sd-bus-provider'), required: get_option('logind'))
endif

logind_deps_found = sdbus.found()
if get_option('logind').enabled() and not logind_deps_found
	error('Building with -Dlogind=enabled, but sd-bus has not been not found')
endif
have_logind = (not get_option('logind').disabled()) and logind_deps_found

if have_logind
	swayidle_deps += sdbus
endif

conf_data = configuration_data()

conf_data.set10('HAVE_LIBSYSTEMD', sdbus.found() and sdbus.name() == 'libsystemd')
conf_data.set10('HAVE_LIBELOGIND', sdbus.found() and sdbus.name() == 'libelogind')
conf_data.set10('HAVE_BASU', sdbus.found() and sdbus.name() == 'basu')
conf_data.set10('HAVE_LOGIND', have_logind)

configure_file(output: 'config.h', configuration: conf_data)

executable(
	'swayidle', [
		'main.c',
	],
	dependencies: swayidle_deps,
	install: true,
)

if scdoc.found()
	sh = find_program('sh')
	mandir = get_option('mandir')
	man_files = [
		'swayidle.1.scd',
	]
	foreach filename : man_files
		topic = filename.split('.')[-3].split('/')[-1]
		section = filename.split('.')[-2]
		output = '@0@.@1@'.format(topic, section)

		custom_target(
			output,
			input: filename,
			output: output,
			command: [
				sh, '-c', '@0@ < @INPUT@ > @1@'.format(scdoc.path(), output)
			],
			install: true,
			install_dir: '@0@/man@1@'.format(mandir, section)
		)
	endforeach
endif

datadir = get_option('datadir')

if get_option('zsh-completions')
	zsh_files = files(
		'completions/zsh/_swayidle',
	)
	zsh_install_dir = datadir + '/zsh/site-functions'

	install_data(zsh_files, install_dir: zsh_install_dir)
endif

if get_option('bash-completions')
	bash_files = files(
		'completions/bash/swayidle',
	)
	if bash_comp.found()
		bash_install_dir = bash_comp.get_pkgconfig_variable('completionsdir')
	else
		bash_install_dir = datadir + '/bash-completion/completions'
	endif

	install_data(bash_files, install_dir: bash_install_dir)
endif

if get_option('fish-completions')
	fish_files = files(
		'completions/fish/swayidle.fish',
	)
	if fish_comp.found()
		fish_install_dir = fish_comp.get_pkgconfig_variable('completionsdir')
	else
		fish_install_dir = datadir + '/fish/vendor_completions.d'
	endif

	install_data(fish_files, install_dir: fish_install_dir)
endif
