if test -x /usr/bin/docker;then
DOCKER=/usr/bin/docker
else
DOCKER=/usr/bin/docker.io
fi

. ./common.sh

ECHO_E="/bin/echo -e"
if test -x /usr/bin/lockfile-create;then
LOCKFILE="lockfile-create docker"
UNLOCKFILE="lockfile-remove docker"
else
LOCKFILE="lockfile docker.lock"
UNLOCKFILE="rm -f docker.lock"
fi

if test -z "$DOCKER_DIR";then
	DOCKER_DIR=docker-ocserv
fi

if ! test -x $DOCKER;then
	echo "The docker program is needed to perform this test"
	exit 77
fi

if test -f /etc/debian_version;then
	DEBIAN=1
fi

if test -f /etc/fedora-release;then
	FEDORA=1
fi

if test -z $FEDORA && test -z $DEBIAN;then
	echo "******************************************************"
	echo "This test requires compiling ocserv in a Debian or Fedora systems"
	echo "******************************************************"
	exit 77
fi

check_for_file() {
	FILENAME=$1
	IMG=$2

	if test -z "$IMG"; then
		IMG=$IMAGE_NAME
	fi

	rm -f out$TMP
	$DOCKER exec $IMG ls $FILENAME >out$TMP
	grep "$FILENAME" out$TMP|grep -v "cannot access"
	if test $? != 0;then
		echo "could not find $FILENAME"
		return 1
	else
		rm -f out$TMP
		return 0
	fi
}

retrieve_user_info() {
	USERNAME=$1
	MATCH=$2
	counter=0
	ret=1

	while [ $counter -lt 4 ]
	do
		$DOCKER exec $IMAGE_NAME occtl show user $USERNAME >out$TMP 2>&1
		if test -z "$MATCH";then
			grep "Username" out$TMP
		else
			grep "$MATCH" out$TMP
		fi
		ret=$?
		if test $ret = 0;then
			break
		fi
		counter=`expr $counter + 1`
		sleep 2
	done
	if test $ret != 0;then
		kill $PID
		cat out$TMP
		echo "could not find user information"
		stop
	else
		rm -f out$TMP
	fi
}

retrieve_route_info() {
	retrieve_user_info $1 $2
}

stop() {
	$DOCKER stop $IMAGE_NAME
	$DOCKER rm $IMAGE_NAME
	exit 1
}

$LOCKFILE
$DOCKER stop $IMAGE_NAME >/dev/null 2>&1
$DOCKER rm $IMAGE_NAME >/dev/null 2>&1

rm -f $DOCKER_DIR/Dockerfile
if test "$FEDORA" = 1;then
	echo "Using the fedora image"
	$DOCKER pull fedora:21
	if test $? != 0;then
		echo "Cannot pull docker image"
		$UNLOCKFILE
		exit 1
	fi
	cp $DOCKER_DIR/Dockerfile-fedora-$CONFIG $DOCKER_DIR/Dockerfile
else #DEBIAN
	echo "Using the Debian image"
	$DOCKER pull debian:jessie
	if test $? != 0;then
		echo "Cannot pull docker image"
		$UNLOCKFILE
		exit 1
	fi
	cp $DOCKER_DIR/Dockerfile-debian-$CONFIG $DOCKER_DIR/Dockerfile
fi

if test ! -f $DOCKER_DIR/Dockerfile;then
	echo "Cannot test in this system"
	$UNLOCKFILE
	exit 77
fi

rm -f $DOCKER_DIR/ocserv $DOCKER_DIR/ocpasswd $DOCKER_DIR/occtl
cp ../src/ocserv ../src/ocpasswd ../src/occtl $DOCKER_DIR/

echo "Creating image $IMAGE"
$DOCKER build -t $IMAGE $DOCKER_DIR/
if test $? != 0;then
	echo "Cannot build docker image"
	$UNLOCKFILE
	exit 1
fi

$UNLOCKFILE
