# Clone from the Fedora 22 image
FROM fedora:25

RUN dnf install -y krb5-libs krb5-workstation libev
RUN dnf install -y gnutls gnutls-utils iproute systemd
RUN dnf install -y bash net-tools nuttcp iputils openssh-clients passwd
RUN dnf install -y lz4 radcli liboauth oathtool procps-ng iputils
RUN dnf install -y openconnect

# To be able to debug
RUN dnf install -y openssh-server strace lsof && dnf clean all
RUN echo 'root:root' | chpasswd
RUN echo set -o vi >> /etc/bashrc

ADD krb5.conf /etc/

RUN useradd -m -p "$6$ZzoUpzPP$PaQoBzfpVCSO23OXB523mgcHaXeVkW/zqYFr84GiItggqo9NK.MAkqMXKuDLybuscuEwxtpAMSNaxTftyaQjT." testuser

ADD ca.pem /etc/

# It's not possible to use mknod inside a container with the default LXC
# template, so we untar it from this archive.
ADD dev-tun.tgz /dev/

RUN ldconfig

CMD sshd-keygen;/usr/sbin/sshd;echo testuser123|kinit testuser@KERBEROS.TEST && /usr/sbin/openconnect kerberos.test --cafile /etc/ca.pem -b && sleep 5 && ping -w 5 192.168.1.1 && kdestroy && ( /usr/sbin/openconnect kerberos.test --cafile /etc/ca.pem --cookieonly --non-inter || touch /tmp/ok1 );echo testuser123|kinit testuser@KERBEROS.TEST && sleep 61 && ( /usr/sbin/openconnect kerberos.test --non-inter --cafile /etc/ca.pem || touch /tmp/ok2 );sleep 3600
