#!/bin/sh -e

test $DEBIAN_SCRIPT_DEBUG && set -v -x

DAEMON=/usr/sbin/snort
NAME=snort
DESC="Network Intrusion Detection System"

CONFIG=/etc/snort/snort.debian.conf
# Old (obsolete) way to provide parameters
if [ -r /etc/snort/snort.common.parameters ] ; then
	COMMON=`cat /etc/snort/snort.common.parameters`
elif [ -r /etc/default/snort ] ; then
# Only read this if the old configuration is not present
	. /etc/default/snort
	COMMON="$PARAMS -l $LOGDIR -u $SNORTUSER -g $SNORTGROUP"
fi

test -x $DAEMON || exit 0
test -f $CONFIG && . $CONFIG
test -z "$DEBIAN_SNORT_HOME_NET" && DEBIAN_SNORT_HOME_NET="192.168.0.0/16"

# to find the lib files
cd /etc/snort

check_log_dir() {
# Does the logging directory belong to Snort?
	# If we cannot determine the logdir return without error
	# (we will not check it)
	# This will only be used by people using /etc/default/snort
	[ -n "$LOGDIR" ] || return 0
	[ -n "$SNORTUSER" ] || return 0
	if [ ! -e "$LOGDIR" ] ; then
		echo -n "ERR: logging directory $LOGDIR does not exist"
		return 1
	elif [ ! -d "$LOGDIR" ] ; then
		echo -n "ERR: logging directory $LOGDIR does not exist"
		return 1
	else
		real_log_user=`stat -c %U $LOGDIR`
	# An alternative way is to check if the snort user can create 
	# a file there...
		if [ "$real_log_user" != "$SNORTUSER" ] ; then
			echo -n "ERR: logging directory $LOGDIR does not belong to the snort user $SNORTUSER"
			return 1
		fi
	fi
	return 0
}

case "$1" in
  start)
        if [ -e /etc/snort/db-pending-config ] ; then
		echo "WARN: /etc/snort/db-pending-config file found"
		echo "WARN: Snort will not start as its database is not yet configured."
		echo "WARN: Please configure the database as described in"
		echo "WARN: /usr/share/doc/snort-{pgsql,mysql}/README-database.Debian"
		echo "WARN: and remove /etc/snort/db-pending-config"
		exit 1
	fi

	echo -n "Starting $DESC: "
        if ! check_log_dir; then
		echo " will not start $DESC!"
		exit 1
	fi
	if [ "$DEBIAN_SNORT_STARTUP" = "dialup" ]; then
		shift
		set +e
		/etc/ppp/ip-up.d/snort "$@"
		exit $?
	fi

	# Usually, we start all interfaces
	interfaces="$DEBIAN_SNORT_INTERFACE"

	# If we are requested to start a specific interface...
	test "$2" && interfaces="$2"

	myret=0
	got_instance=0
	for interface in $interfaces; do
		got_instance=1
		echo -n "$NAME($interface)"

		PIDFILE=/var/run/snort_$interface.pid

		fail="failed (check /var/log/daemon.log)"
		/sbin/start-stop-daemon --stop --signal 0 --quiet \
			--pidfile "$PIDFILE" --exec $DAEMON >/dev/null &&
				fail="already running"

		CONFIGFILE=/etc/snort/snort.$interface.conf
		if [ ! -e "$CONFIGFILE" ]; then
			echo "using /etc/snort/snort.conf"
			CONFIGFILE=/etc/snort/snort.conf
		else
			echo "using /etc/snort/snort.$interface.conf"
                fi

		set +e
		/sbin/start-stop-daemon --start --quiet --pidfile "$PIDFILE" \
			--exec $DAEMON -- $COMMON $DEBIAN_SNORT_OPTIONS \
			-c $CONFIGFILE \
			-S "HOME_NET=[$DEBIAN_SNORT_HOME_NET]" \
			-i $interface >/dev/null
		ret=$?
		set -e
		case "$ret" in
			0)
				echo "."
				;;
			*)
				echo "...$fail."
				myret=$(expr "$myret" + 1)
				;;
		esac
	done

	if [ "$got_instance" = 0 ]; then
		echo "No snort instance found to be started!" >&2
		exit 1
	fi

	exit $myret
	;;
  stop)
	if [ "$DEBIAN_SNORT_STARTUP" = "dialup" ]; then
		shift
		set +e
		/etc/ppp/ip-down.d/snort "$@"
		exit $?
	fi

	# Usually, we stop all current running interfaces
	pidpattern=/var/run/snort_*.pid

	# If we are requested to stop a specific interface...
	test "$2" && pidpattern=/var/run/snort_"$2".pid

	got_instance=0
	for PIDFILE in $pidpattern; do
		# This check is also needed, if the above pattern doesn't match
		test -f "$PIDFILE" || continue

		got_instance=1
		interface=$(basename "$PIDFILE" .pid | sed -e 's/^snort_//')

		echo -n "Stopping $DESC: $NAME($interface)"

		/sbin/start-stop-daemon --stop --retry 5 --quiet --oknodo \
			--pidfile "$PIDFILE" --exec $DAEMON >/dev/null
		rm -f "$PIDFILE"

		echo "."
	done

	if [ "$got_instance" = 0 ]; then
		echo "No snort instance found to be stopped!" >&2
	fi
	;;
  restart|force-restart|reload|force-reload)
	# Usually, we restart all current running interfaces
	pidpattern=/var/run/snort_*.pid

	# If we are requested to restart a specific interface...
	test "$2" && pidpattern=/var/run/snort_"$2".pid

	got_instance=0
	for PIDFILE in $pidpattern; do
		# This check is also needed, if the above pattern doesn't match
		test -f "$PIDFILE" || continue

		got_instance=1
		interface=$(basename "$PIDFILE" .pid | sed -e 's/^snort_//')
		$0 stop $interface || true
		$0 start $interface || true
	done

	if [ "$got_instance" = 0 ]; then
		echo "No snort instance found to be restarted!" >&2
	fi
	;;
  status)
        echo -n "Status of snort daemon(s):"
	interfaces="$DEBIAN_SNORT_INTERFACE"
	# If we are requested to check for a specific interface...
	test "$2" && interfaces="$2"
	for interface in $interfaces; do
                echo -n " $interface "
                pidfile=/var/run/snort_$interface.pid
                if [ -f  "$pidfile" ] ; then
 	                pidval=`cat $pidfile`
		        if ps -p $pidval | grep -q snort; then
		       		echo -n "(ok)"
			else
				echo -n "(nok!)"
			fi
                 else
                        echo -n "(nok!)"
                 fi
        done
        echo "."
        ;;
  config-check)
	if [ "$DEBIAN_SNORT_STARTUP" = "dialup" ]; then
		echo "Config-check is currently not supported for snort in Dialup configuration"
		exit 0
	fi

	# usually, we test all interfaces
	interfaces="$DEBIAN_SNORT_INTERFACE"
	# if we are requested to test a specific interface...
	test "$2" && interfaces="$2"

	myret=0
	got_instance=0
	for interface in $interfaces; do
		got_instance=1
		echo -n "checking $desc config: $name($interface)"

		CONFIGFILE=/etc/snort/snort.$interface.conf
		if [ ! -e "$CONFIGFILE" ]; then
			CONFIGFILE=/etc/snort/snort.conf
		fi
		COMMON=`echo $COMMON | sed -e 's/-D//'`
		set +e
		$DAEMON -T $COMMON $DEBIAN_SNORT_OPTIONS \
			-c $CONFIGFILE \
			-S "HOME_NET=[$DEBIAN_SNORT_HOME_NET]" \
			-i $interface >/dev/null 2>&1
		ret=$?
		set -e
		case "$ret" in
			0)
				echo ".ok."
				;;
			*)
				echo "...failed."
				myret=$(expr "$myret" + 1)
				;;
		esac
	done
	if [ "$got_instance" = 0 ]; then
		echo "no snort instance found to be started!" >&2
		exit 1
	fi

	exit $myret
	;;
  *)
	echo "Usage: $0 {start|stop|restart|force-restart|reload|force-reload|status|config-check}"
	exit 1
	;;
esac
exit 0
