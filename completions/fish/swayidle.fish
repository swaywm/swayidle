# swayidle
set -l all_events timeout
set -l time_events timeout

complete -c swayidle --arguments "$all_events"
complete -c swayidle --condition "__fish_seen_subcommand_from $time_events" --exclusive

complete -c swayidle -s h --description 'show help'
complete -c swayidle -s d --description 'debug'
complete -c swayidle -s w --description 'wait for command to finish'
