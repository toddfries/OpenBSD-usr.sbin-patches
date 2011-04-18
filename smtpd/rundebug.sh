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
newcmd $smtpd -f /etc/mail/smtpd.conf.new -d
sleep 3
for p in $(pgrep smtpd)
do
	newcmd gdb $smtpd $p
done
