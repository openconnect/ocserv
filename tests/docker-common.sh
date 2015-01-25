if test -x /usr/bin/docker;then
DOCKER=/usr/bin/docker
else
DOCKER=/usr/bin/docker.io
fi

if test -x /usr/bin/lockfile-create;then
LOCKFILE="lockfile-create docker"
UNLOCKFILE="lockfile-remove docker"
else
LOCKFILE="lockfile docker.lock"
UNLOCKFILE="rm -f docker.lock"
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

$LOCKFILE
if test "$UNIX" = 1;then
	$DOCKER stop test_unix >/dev/null 2>&1
	$DOCKER rm test_unix >/dev/null 2>&1
else
	$DOCKER stop test_ocserv >/dev/null 2>&1
	$DOCKER rm test_ocserv >/dev/null 2>&1
fi

if test "$FEDORA" = 1;then
	echo "Using the fedora image"
	$DOCKER pull fedora:21
	if test $? != 0;then
		echo "Cannot pull docker image"
		$UNLOCKFILE
		exit 1
	fi
	cp docker-ocserv/Dockerfile-fedora-$CONFIG docker-ocserv/Dockerfile
else #DEBIAN
	echo "Using the Debian image"
	$DOCKER pull debian:jessie
	if test $? != 0;then
		echo "Cannot pull docker image"
		$UNLOCKFILE
		exit 1
	fi
	cp docker-ocserv/Dockerfile-debian-$CONFIG docker-ocserv/Dockerfile
fi

cp ../src/ocserv ../src/ocpasswd ../src/occtl docker-ocserv/

echo "Creating image $IMAGE"
$DOCKER build -t $IMAGE docker-ocserv/
if test $? != 0;then
	echo "Cannot build docker image"
	$UNLOCKFILE
	exit 1
fi

$UNLOCKFILE
