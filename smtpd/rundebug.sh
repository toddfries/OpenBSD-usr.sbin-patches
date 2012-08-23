td=$(mktemp -d /tmp/.rundebug.XXXXXXXXXXXXXXXXXXXX)

{
	echo handle SIGPIPE nostop print pass
	echo handle SIGTERM nostop print pass
	echo handle SIGHUP  nostop print pass
	echo cont
} > $td/gdbcmds

pkill smtpd
while pgrep smtpd; do sleep 1; done

if [ "$DISPLAY" ]; then
	newcmd() {
		xterm -e "$@" &
	}
else
	newcmd() {
		tmux new-window -d "$@"
	}
fi

if [ -f smtpd/obj/smtpd ]; then
	smtpd=./smtpd/obj/smtpd
else
	smtpd=./smtpd/smtpd
fi
newcmd $smtpd -f /etc/mail/smtpd.conf -d
sleep 3
for p in $(pgrep smtpd)
do
	newcmd gdb -x $td/gdbcmds -batch $smtpd $p
done
sleep 30
rm -rf "$td"
