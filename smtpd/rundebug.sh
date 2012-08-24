td=$(mktemp -d /tmp/.rundebug.XXXXXXXXXXXXXXXXXXXX)

{
	echo handle SIGPIPE nostop print pass
	echo handle SIGTERM nostop print pass
	echo handle SIGHUP  nostop print pass
	echo handle SIGINT  nostop print pass
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
		tmux new-window "$*"
	}
fi

if [ -x ./smtpd/obj/smtpd ]; then
	smtpd=./smtpd/obj/smtpd
else
	if [ -x ./smtpd/smtpd ]; then
		smtpd=./smtpd/smtpd
	else
		smtpd=./src/smtpd
	fi
fi
newcmd sudo $smtpd -f /etc/mail/smtpd.conf -vd -T all
sleep 5
for p in $(pgrep smtpd)
do
	newcmd sudo gdb -x $td/gdbcmds $smtpd $p
done
sleep 30
rm -rf "$td"
