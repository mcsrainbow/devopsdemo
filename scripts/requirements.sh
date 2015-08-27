#!/bin/bash

function require_os(){
  sudo yum groupinstall "Development tools"
  sudo yum install zlib-devel bzip2-devel openssl-devel ncurses-devel
  sudo yum install python-setuptools python-devel
}

function require_virtualenv(){
  sudo yum install http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm
  sudo yum install python-pip
  sudo easy_install virtualenv
}

function require_flask(){
  mkdir -p ~/devopsdemo
  cd ~/devopsdemo
  virtualenv flask
  . flask/bin/activate
  pip install -r flask/requirements.txt
}

function require_mysql(){
  cd ~/devopsdemo
  . flask/bin/activate
  sudo yum install http://www.percona.com/redir/downloads/percona-release/redhat/latest/percona-release-0.1-3.noarch.rpm
  sudo yum install Percona-Server-devel Percona-Server-shared-compat Percona-Server-client-55 Percona-Server-shared-55
  sudo yum install Percona-Server-server-55
  easy_install -U distribute
  pip install mysql-python torndb
}

function require_misc(){
  cd ~/devopsdemo
  . flask/bin/activate
  pip install argparse requests paramiko
  mkdir -p sshkeys tmp
}

case $1 in
  all)
    require_os
    require_virtualenv
    require_flask
    require_mysql
    require_misc
    ;;
  os)
    require_os
    ;;
  virtualenv)
    require_virtualenv
    ;;
  flask)
    require_flask
    ;;
  mysql)
    require_mysql
    ;;
  misc)
    require_misc
    ;;
  *)
    echo $"Usage: $0 {all|os|virtualenv|flask|mysql|misc}"
    exit 2
esac
