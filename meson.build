project(
	'swayidle',
	'c',
	version: '1.5',
	license: 'MIT',
	meson_version: '>=0.48.0',
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

wayland_client = dependency('wayland-client')
wayland_protos = dependency('wayland-protocols', version: '>=1.14')
wayland_server = dependency('wayland-server')
logind = dependency('lib' + get_option('logind-provider'), required: get_option('logind'))

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

conf_data = configuration_data()
conf_data.set10('HAVE_SYSTEMD', false)
conf_data.set10('HAVE_ELOGIND', false)

if logind.found()
	swayidle_deps += logind
	conf_data.set10('HAVE_' + get_option('logind-provider').to_upper(), true)
endif

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
	bash_install_dir = datadir + '/bash-completion/completions'

	install_data(bash_files, install_dir: bash_install_dir)
endif

if get_option('fish-completions')
	fish_files = files(
		'completions/fish/swayidle.fish',
	)
	fish_install_dir = datadir + '/fish/completions'

	install_data(fish_files, install_dir: fish_install_dir)
endif
