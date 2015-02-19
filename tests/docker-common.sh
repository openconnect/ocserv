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
