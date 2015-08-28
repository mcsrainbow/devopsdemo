from flask import render_template, flash, redirect, session, url_for, request, g
from flask.ext.login import login_user, logout_user, current_user, login_required
from app import app, db, lm
from app.models import User


@lm.user_loader
def load_user(uid):
    return User.query.get(int(uid))


@app.before_request
def before_request():
    g.user = current_user


@app.route('/')
@app.route('/index')
@login_required
def index():
    posts = [{ 'author': { 'nickname': 'Dong' }, 
               'body': 'Bootstrap is beautiful, and Flask is cool!' }]
    return render_template('index.html',posts=posts)


@app.route('/status')
@login_required
def status():
    from app.utils.operations import local
    from decimal import Decimal
    
    os_fqdn = local('hostname --fqdn')

    os_release = local('cat /etc/*-release |head -n 1 |cut -d= -f2 |sed s/\\"//g')

    mem_kb = local("""grep -w "MemTotal" /proc/meminfo |awk '{print $2}'""")
    mem_mb = Decimal(mem_kb) / 1024
    os_memory = round(mem_mb,2)

    cpu_type = local("""grep 'model name' /proc/cpuinfo |uniq |awk -F : '{print $2}' |sed 's/^[ \t]*//g' |sed 's/ \+/ /g'""")
    cpu_cores = local("""grep 'processor' /proc/cpuinfo |sort |uniq |wc -l""")

    nics = local("""/sbin/ifconfig |grep "Link encap" |awk '{print $1}' |grep -wv 'lo' |xargs""")
    nics_list = nics.split()
    t_nic_info = ""
    for i in nics_list:
        ipaddr = local("""/sbin/ifconfig %s |grep -w "inet addr" |cut -d: -f2 | awk '{print $1}'""" % (i))
        if ipaddr:
            t_nic_info = t_nic_info + i + ":" + ipaddr + ", "

    disk_usage = local("""df -hP |grep -Ev 'Filesystem|tmpfs' |awk '{print $3"/"$2" "$5" "$6", "}' |xargs""")

    top_info = local('top -b1 -n1 |head -n 5')
    top_info_list = top_info.split('\n')

    return render_template('status.html',
                            os_fqdn=os_fqdn,
                            os_release=os_release,
                            os_memory=os_memory,
                            cpu_type=cpu_type,
                            cpu_cores=cpu_cores,
                            os_network=t_nic_info,
                            disk_usage=disk_usage,
                            top_info_list=top_info_list)


@app.route('/operations', methods=['GET', 'POST'])
@login_required
def operations():
    import paramiko
    from app.utils.operations import remote
    from config import basedir
    from app.forms import OperationsForm

    def isup(hostname):
        import socket
    
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(2)
        try:
            conn.connect((hostname,22))
            conn.close()
        except:
            return False
        return True

    form = OperationsForm()
    if form.validate_on_submit():
        username = 'dong'
        pkey = basedir + '/sshkeys/id_rsa'

        hostname = form.hostname.data
        cmd = form.cmd.data

        if not isup(hostname):
            return render_template('operations.html',form=form,failed_host=hostname)

        blacklist = ['reboot', 'shutdown', 'poweroff',
                     'rm', 'mv', '-delete', 'source', 'sudo',
                     '<', '<<', '>>', '>']
        for item in blacklist:
            if item in cmd.split():
                return render_template('operations.html',form=form,blacklisted_word=item)

        try:
            out = remote(cmd,hostname=hostname,username=username,pkey=pkey)
        except paramiko.AuthenticationException:
            return render_template('operations.html',form=form,hostname=hostname,failed_auth=True)
        
        failed_cmd = out.failed
        succeeded_cmd = out.succeeded

        return render_template('operations.html',
                                form=form,
                                cmd=cmd,
                                hostname=hostname,
                                out=out,
                                failed_cmd=failed_cmd,
                                succeeded_cmd=succeeded_cmd)

    return render_template('operations.html',form=form)


@app.route('/racktables', methods=['GET', 'POST'])
@login_required
def racktables():
    from app.utils.operations import local
    from config import basedir
    from app.forms import RacktablesForm

    form = RacktablesForm()
    if form.validate_on_submit():
        param_do = form.do_action.data
        objectname = form.objectname.data
        objecttype = form.objecttype.data
        param_s = form.rackspace.data
        param_p = form.rackposition.data

        script = basedir + "/scripts/racktables.py"

        if param_do == 'help':
            cmd = "{0} -h".format(script)

        if param_do == 'get':
            cmd = "{0}".format(script)
            if objectname:
                cmd = "{0} {1}".format(script,objectname)

        if param_do == 'list':
            cmd = "{0} {1} -l".format(script,objectname)

        if param_do == 'read':
            cmd = "{0} {1} -r".format(script,objectname)
            if objecttype == 'offline_mode':
                cmd = cmd + " -o"
            if objecttype == 'patch_panel':
                cmd = cmd + " -b"
            if objecttype == 'network_switch':
                cmd = cmd + " -n"
            if objecttype == 'network_security':
                cmd = cmd + " -f"
            if objecttype == 'pdu':
                cmd = cmd + " -u"

        if param_do == 'write':
            cmd = "{0} {1} -w".format(script,objectname)
            if param_s:
                cmd = cmd + " -s {0}".format(param_s)
            if param_p != 'none':
                cmd = cmd + " -p {0}".format(param_p)
            if objecttype == 'offline_mode':
                cmd = cmd + " -o"
            if objecttype == 'patch_panel':
                cmd = cmd + " -b"
            if objecttype == 'network_switch':
                cmd = cmd + " -n"
            if objecttype == 'network_security':
                cmd = cmd + " -f"
            if objecttype == 'pdu':
                cmd = cmd + " -u"

        if param_do == 'delete':
            cmd = "{0} {1} -d".format(script,objectname)

        out = local(cmd)

        failed_cmd = out.failed
        succeeded_cmd = out.succeeded

        return render_template('racktables.html',
                                form=form,
                                cmd=cmd,
                                out=out,
                                failed_cmd=failed_cmd,
                                succeeded_cmd=succeeded_cmd)
    
    return render_template('racktables.html',form=form)


@app.route('/hadoop', methods=['GET', 'POST'])
@login_required
def hadoop():
    import paramiko
    from app.utils.operations import remote
    from config import basedir
    from app.forms import HadoopForm

    def isup(hostname):
        import socket

        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(2)
        try:
            conn.connect((hostname,22))
            conn.close()
        except:
            return False
        return True

    form = HadoopForm()
    if form.validate_on_submit():
        username = 'dong'
        pkey = basedir + '/sshkeys/id_rsa'

        param_do = form.do_action.data
        slave_hostname = form.slave_hostname.data
        master_hostname = form.master_hostname.data

        if master_hostname == 'none':
            return render_template('hadoop.html',form=form,none_host=True)

        if master_hostname in ['idc1-hnn1', 'idc2-hnn1']:
            script = '/root/bin/excludedn'

        if master_hostname in ['idc1-hrm1', 'idc2-hrm1']:
            script = '/root/bin/excludeyn'

        if param_do == 'exclude':
            cmd = "sudo {0} {1}".format(script,slave_hostname)

        if param_do == 'recover':
            cmd = "sudo {0} -r {1}".format(script,slave_hostname)

        if not isup(master_hostname):
            return render_template('hadoop.html',form=form,failed_host=master_hostname)

        try:
            out = remote(cmd,hostname=master_hostname,username=username,pkey=pkey)
        except paramiko.AuthenticationException:
            return render_template('hadoop.html',form=form,master_hostname=master_hostname,failed_auth=True)

        failed_cmd = out.failed
        succeeded_cmd = out.succeeded

        return render_template('hadoop.html',
                                form=form,
                                cmd=cmd,
                                master_hostname=master_hostname,
                                out=out,
                                failed_cmd=failed_cmd,
                                succeeded_cmd=succeeded_cmd)

    return render_template('hadoop.html',form=form)


@app.route('/editor', methods=['GET', 'POST'])
@login_required
def editor():
    import os
    import time
    from hashlib import md5
    from app.utils.operations import local
    from app.forms import EditorForm

    form = EditorForm()
    if form.validate_on_submit():
        param_do = form.do_action.data
        file_path = form.file_path.data

        if param_do == 'read':
            file_access = os.access(file_path, os.W_OK)
            if not file_access:
                return render_template('editor.html',
                                        form=form,
                                        file_path=file_path,
                                        file_access=file_access)

            with open(file_path, 'rb') as f:
                file_data = f.read()
            f.closed
            form.file_data.data=file_data
            return render_template('editor.html',
                                    form=form,
                                    file_path=file_path,
                                    file_access=file_access)

        if param_do == 'save':
            file_access = os.access(file_path, os.W_OK)
            if not file_access:
                return render_template('editor.html',
                                        form=form,
                                        file_path=file_path,
                                        file_access=file_access)

            file_md5sum = md5(open(file_path, 'rb').read()).hexdigest()
            form_md5sum = md5(form.file_data.data.replace('\r\n','\n')).hexdigest()
            if file_md5sum == form_md5sum:
                return render_template('editor.html',
                                        form=form,
                                        file_path=file_path,
                                        file_access=file_access,
                                        file_no_change=True)


            postfix = time.strftime("%Y%m%d%H%M%S")
            file_backup = file_path + "." + postfix

            backup_out = local("cp -p {0} {1}".format(file_path,file_backup))
            succeeded_backup = backup_out.succeeded
            failed_backup = backup_out.failed

            file = open(file_path, 'wb')
            file.write(form.file_data.data.replace('\r\n','\n'))
            file.close()
    
        return render_template('editor.html',
                                form=form,
                                file_path=file_path,
                                file_access=file_access,
                                postfix=postfix,
                                backup_out=backup_out,
                                failed_backup=failed_backup,
                                succeeded_backup=succeeded_backup)

    return render_template('editor.html',form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    from app.forms import SignupForm
   
    form = SignupForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user is not None:
            form.email.errors.append("The Email address is already taken.")
            return render_template('signup.html', form=form)

        newuser = User(form.firstname.data,form.lastname.data,form.email.data,form.password.data)
        db.session.add(newuser)
        db.session.commit()

        session['email'] = newuser.email
        return redirect(url_for('login'))
   
    return render_template('signup.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user is not None and g.user.is_authenticated():
        return redirect(url_for('index'))

    from app.forms import LoginForm

    form = LoginForm()
    if form.validate_on_submit():
        session['remember_me'] = form.remember_me.data
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user and user.check_password(form.password.data):
            session['email'] = form.email.data
            login_user(user,remember=session['remember_me'])
            return redirect(url_for('index'))
        else:
            return render_template('login.html',form=form,failed_auth=True)
                   
    return render_template('login.html',form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))
