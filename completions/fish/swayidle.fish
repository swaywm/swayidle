# swayidle
set -l all_events timeout before-sleep after-resume lock unlock idlehint
set -l cmd_events before-sleep after-resume lock unlock
set -l time_events idlehint timeout

complete -c swayidle --arguments "$all_events"
complete -c swayidle --condition "__fish_seen_subcommand_from $cmd_events" --require-parameter
complete -c swayidle --condition "__fish_seen_subcommand_from $time_events" --exclusive

complete -c swayidle -s h --description 'show help'
complete -c swayidle -s d --description 'debug'
complete -c swayidle -s w --description 'wait for command to finish'
