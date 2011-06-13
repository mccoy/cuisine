# -----------------------------------------------------------------------------
# Project   : Cuisine - Functions to write Fabric recipies
# -----------------------------------------------------------------------------
# Author    : Sebastien Pierre                            <sebastien@ffctn.com>
# Author    : Thierry Stiegler   (gentoo port)     <thierry.stiegler@gmail.com>
# Author    : Jim McCoy (distro checks and rpm port)      <jim.mccoy@gmail.com>
# License   : Revised BSD License
# -----------------------------------------------------------------------------
# Creation  : 26-Apr-2010
# Last mod  : 27-Oct-2010
# -----------------------------------------------------------------------------

import fabric, fabric.api, fabric.context_managers
import os, base64, bz2, string, re, time, subprocess

__doc__ = """
Cuisine makes it easy to write automatic server installation and configuration
recipies by wrapping common administrative tasks (installing packages, creating users
and groups) in Python functions.

Cuisine is designed to work with Fabric and provide all you need for getting
your new server up and running in minutes.

"""

# See <http://lethain.com/entry/2008/nov/04/deploying-django-with-fabric/>
# and <http://www.saltycrane.com/blog/2009/10/notes-python-fabric-09b1/>
# http://blog.markfeeney.com/2009/12/ec2-fabric-and-err-stdin-is-not-tty.html

MODE = "user"
RE_SPACES = re.compile("[\s\t]+")

##
##
##  Note to anyone seeing this fork right now:  I am a bad person and I am going
##  to leave my various notes about things to do scattered in this file instead of
##  pushing a clean branch up to github and using a local branch for these notes.
##  Sorry about being lazy, but if you see a comment prefixed with JIM: then this
##  is just a note to myself so that I do not forget to fix/finish something...
##
##

## Jim's Changelog:
##     - Added redhat/yum compatibity and a bit of framework for dealing with distros.
##     - Added a few more options for some functions.
##     - Changed a lot of run() calls into sudo() calls since the general purpose
##       of this package is sysadmin tasks and a lot of them require running as root.
##     - Cleaned up the package installation bits to remove some extraneous remote calls
##       that did things like check for existing installs when just blindly re-running
##       the install would have no downside.
##     - The "update" arg in package management functions used to update the package
##       manager cache, now the updates happen automatically after a certain amount of
##       time and the "upgrade" option was added to package management functions to
##       signal when we want to upgrade a package if possible.
##     - The passwd file manipulation functions can now also update user passwords.
##     - The minimal service checker was expanded to now start/stop services and to
##       set services to start up at various runlevels.
##     - ssh_keygen can now do rsa keys in addition to dsa keys

# JIM: Assume that systems do not switch back and forth between debian/redhat more
# often than you import/run this module...  The HOST_INFO_MAP bits should probably
# get stuffed into some part of env, but for now it is a module global variable (another
# option in the interim would be to make this a module-level singleton object with the
# right property attrs to know when to do lookups, etc.)  [Examine how tav's fabric modes
# do the config_file bits and go with that...]
HOST_INFO_MAP={}
PKG_DB_UPDATE_FREQ=300

def mode_user():
	"""Cuisine functions will be executed as the current user."""
	global MODE
	MODE = "user"

def mode_sudo():
	"""Cuisine functions will be executed with sudo."""
	global MODE
	MODE = "sudo"

def run(*args, **kwargs):
	"""A wrapper to Fabric's run/sudo commands, using the 'cuisine.MODE' global
	to tell wether the command should be run as regular user or sudo."""
	if MODE == "sudo":
		return fabric.api.sudo(*args, **kwargs)
	else:
		return fabric.api.run(*args, **kwargs)

def sudo(*args, **kwargs):
	"""A wrapper to Fabric's run/sudo commands, using the 'cuisine.MODE' global
	to tell wether the command should be run as regular user or sudo."""
	return fabric.api.sudo(*args, **kwargs)

def multiargs(function):
	"""Decorated functions will be 'map'ed to every element of the first argument
	if it is a list or a tuple, otherwise the function will execute normally."""
	def wrapper(*args, **kwargs):
		if len(args) == 0:
			return function()
		arg = args[0] ; args = args[1:]
		if type(arg) in (tuple, list):
			return map(lambda _:function(_,*args,**kwargs), arg)
		else:
			return function(arg, *args, **kwargs)
	return wrapper

def text_get_line(text, predicate):
	"""Returns the first line that matches the given predicate."""
	for line in text.split("\n"):
		if predicate(line):
			return line
	return ""

def text_normalize(text):
	"""Converts tabs and spaces to single space and strips the text."""
	return RE_SPACES.sub(" ", text).strip()

def text_nospace(text):
	"""Converts tabs and spaces to single space and strips the text."""
	return RE_SPACES.sub("", text).strip()

def text_replace_line(text, old, new, find=lambda old,new:old == new, process=lambda _:_):
	"""Replaces lines equal to 'old' with 'new', returning the new text and the
	count of replacements."""
	res = []
	replaced = 0
	for line in text.split("\n"):
		if find(process(line), process(old)):
			res.append(new)
			replaced += 1
		else:
			res.append(line)
	return "\n".join(res), replaced

def text_ensure_line(text, *lines):
	"""Ensures that the given lines are present in the given text, otherwise appends the lines
	that are not already in the text at the end of it."""
	res = list(text.split("\n"))
	for line in lines:
		assert line.find("\n") == -1, "No EOL allowed in lines parameter: " + repr(line)
		found = False
		for l in res:
			if l == res:
				found = True
				break
		if not found:
			res.append(line)
	return "\n".join(res)

def text_strip_margin( text, margin="|"):
	res = []
	for line in text.split("\n"):
		l = line.split(margin,1)
		if len(l) == 2:
			_, line = l
			res.append(line)
	return "\n".join(res)

def text_template( text, variables ):
	"""Substitutes '${PLACEHOLDER}'s within the text with the
	corresponding values from variables."""
	template = string.Template(text)
	return template.safe_substitute(variables)

def local_read( location ):
	"""Reads a *local* file from the given location, expanding '~' and shell variables."""
	p = os.path.expandvars(os.path.expanduser(location))
	f = file(p, 'rb')
	t = f.read()
	f.close()
	return t

def file_read( location ):
	"""Reads the *remote* file at the given location."""
	return sudo("cat '%s'" % (location))

def file_exists( location ):
	"""Tests if there is a *remote* file at the given location."""
	return run("test -f '%s' && echo OK ; true" % (location)) == "OK"

def file_attribs(location, mode=None, owner=None, group=None, recursive=False):
	"""Updates the mode/owner/group for the remote file at the given location."""
	recursive = recursive and "-R " or ""
	if mode:  sudo("chmod %s %s '%s'" % (recursive, mode,  location))
	if owner: sudo("chown %s %s '%s'" % (recursive, owner, location))
	if group: sudo("chgrp %s %s '%s'" % (recursive, group, location))

def get_fs_attribs(location):
	"""Get the mode, owner, and group for a remote file."""
	fs_check = sudo("test -e '%s' && find '%s' -prune -printf '%s %U %G\n'")
	if len(fs_check) > 0:
		(mode, owner, group) = fs_check.split("")
		return {'mode': mode, 'owner': owner, 'group':group }
	
def file_write( location, content, mode=None, owner=None, group=None ):
	"""Writes the given content to the file at the given remote location, optionally
	setting mode/owner/group."""
	# Hides the output, which is especially important
	with fabric.context_managers.settings(
		fabric.api.hide('warnings', 'running', 'stdout'),
		warn_only=True
    ):
		# We use bz2 compression
		run("echo '%s' | base64 -d | bzcat > \"%s\"" % (base64.b64encode(bz2.compress(content)), location))
		file_attribs(location, mode, owner, group)

def file_update( location, updater=lambda x:x):
	"""Updates the content of the given by passing the existing content of the remote file
	at the given location to the 'updater' function.

	For instance, if you'd like to convert an existing file to all uppercase, simply do:

	>   file_update("/etc/myfile", lambda _:_.upper())
	"""
	assert file_exists(location), "File does not exists: " + location
	new_content = updater(file_read(location))
	assert type(new_content) in (str, unicode, fabric.operations._AttributeString) \
	,"Updater must be like (string)->string, got: %s() = %s" % (updater, type(new_content))
	run("echo '%s' | base64 -d > \"%s\"" % (base64.b64encode(new_content), location))

def file_append( location, content, use_sudo=False, partial=False, escape=True):
	"""Wrapper for fabric.contrib.files.append."""
	fabric.contrib.files.append(location, content, use_sudo, partial, escape)

def dir_attribs(location, mode=None, owner=None, group=None, recursive=False):
	"""Updates the mode/owner/group for the given remote directory."""
	file_attribs(location, mode, owner, group, recursive)

def dir_exists( location ):
	"""Tells if there is a remote directory at the given location."""
	return run("test -d '%s' && echo OK ; true" % (location)).endswith("OK")

def dir_ensure( location, recursive=False, mode=None, owner=None, group=None ):
	"""Ensures that there is a remote directory at the given location, optionnaly
	updating its mode/owner/group.

	If we are not updating the owner/group then this can be done as a single
	ssh call, so use that method, otherwise set owner/group after creation."""
	if mode:
		mode_arg = "-m %s" % (mode)
	else:
		mode_arg = ""
	sudo("(test -d '%s' || mkdir %s %s '%s') && echo OK ; true" % (location, recursive and "-p" or "", mode_arg, location))
	if owner or group:
		dir_attribs(location, owner=owner, group=group)

def command_check( command ):
	"""Tests if the given command is available on the system."""
	return run("which '%s' >& /dev/null && echo OK ; true" % command).endswith("OK")

def distro_check():
	"""Determines the distro and package manager for a remote host and caches it for future reference"""
	global HOST_INFO_MAP
	if fabric.api.env.host in HOST_INFO_MAP and 'distro' in HOST_INFO_MAP[fabric.api.env.host].keys():
		return HOST_INFO_MAP[fabric.api.env.host]
	if fabric.api.env.host not in HOST_INFO_MAP:
		HOST_INFO_MAP[fabric.api.env.host]={}
	# These next two checks will try to figure out the distro on the remote host and what pacakge
	# manager is available.  Make the checks in order of preference, the first hit in each check will
	# be returned as the "correct" selection for that host.
	#
	# Determine distro
	distro_check=r"""if [ -r /etc/lsb-release ]; then
echo $(grep 'DISTRIB_ID' /tmp/lsb-release | sed 's/DISTRIB_ID=//' | head -1 | tr '[:upper:]' '[:lower:]');
else
echo $(find /etc/ -maxdepth 1 -name '*[-_]release' -o -name '*[-_]version' 2> /dev/null |
sed 's#/etc/##;s/[_-]version//;s/[-_]release//' | head -1 | tr '[:upper:]' '[:lower:]');
fi"""
	distro = run(distro_check)
	if len(distro) == 0:
		HOST_INFO_MAP[fabric.api.env.host]['distro']=None
	else:
		HOST_INFO_MAP[fabric.api.env.host]['distro']=distro
	# Determine package manager
	package_manager_check=r"""((which yum >& /dev/null && echo 'yum') ||
(which apt-get >& /dev/null && echo 'apt-get') ||
(which emerge >& /dev/null && echo 'emerge')); true"""
	package_manager = run(package_manager_check)
	if len(package_manager) == 0:
		HOST_INFO_MAP[fabric.api.env.host]['pkg_mgr']=None
	else:
		HOST_INFO_MAP[fabric.api.env.host]['pkg_mgr']=package_manager
	# Determine package manager helper if necessary (something that will tell us what package to
	# install so that we get command X)
       	if package_manager == "apt-get":
		helper_check = run("which apt-file >& /dev/null %% echo 'apt-file'")
		if helper_check=="apt-file":
			HOST_INFO_MAP[fabric.api.env.host].setdefault('pkg_mgr_helpers', []).append('apt-file')
	return HOST_INFO_MAP[fabric.api.env.host]

def package_db_update( force=False ):
	"""Update the package datebase if necessary."""
	now=time.time()
	global PKG_DB_UPDATE_FREQ
	global HOST_INFO_MAP
	distro_info = distro_check()
	last_check = distro_info.get('db_update', 0)
	if force or last_check+PKG_DB_UPDATE_FREQ < now:
		package_manager=distro_info.get('pkg_mgr')
		if package_manager == 'yum':
			sudo("yum makecache >& /dev/null")
			HOST_INFO_MAP[fabric.api.env.host]['db_update'] = now
		elif package_manager == 'apt-get':
			sudo("apt-get --yes update >& /dev/null")
			if 'apt-file' in distro_info.get('pkg_mgr_helpers', []):
				sudo("apt-file update")
			HOST_INFO_MAP[fabric.api.env.host]['db_update'] = now
		elif package_manager == 'emerge':
			sudo("emerge --sync -q >& /dev/null")
			HOST_INFO_MAP[fabric.api.env.host]['db_update'] = now

def package_update( package, db_update=False, use_flags=None ):
	"""Update the package or list of packages given as argument."""
	package_db_update(db_update)
	if type(package) in (list,tuple): package = " ".join(package)
	package_manager=distro_check().get('pkg_mgr')
	if package_manager == 'yum':
		sudo("yum upgrade -y " +package)
	elif package_manager == 'apt-get':
		sudo("apt-get --yes upgrade " + package)
	elif package_manager == 'emerge':
		### XXX: FIX THIS
		sudo("")

def package_install( package, upgrade=False, db_update=False, use_flags=None ):
	"""Installs the given package/list of package, optionaly upgrading an already
	installed package."""
	package_db_update(db_update)
	if type(package) in (list,tuple): package = " ".join(package)
	package_manager=distro_check().get('pkg_mgr')
	if package_manager == 'apt-get':
		sudo("apt-get --yes install " + package)
	elif package_manager == 'yum':
		sudo("yum install -y " +package)
	elif package_manager == 'emerge':
		sudo("%s emerge %s" % (package_use_flags(use_flags), package))
	# Rather than figuring out what is out of date just install first and upgrade second.
	if upgrade:
		package_update(package)



def package_remove( package, db_update=False ):
	"""Remove the package or list of packages given as argument."""
	package_db_update(db_update)
	if type(package) in (list,tuple): package = " ".join(package)
	package_manager=distro_check().get('pkg_mgr')
	if package_manager == 'yum':
		sudo("yum erase -y " + package)
	elif package_manager == 'apt-get':
		sudo("apt-get --yes remove " + package)
	elif package_manager == 'emerge':
		sudo("emerge -C " + package)

def package_use_flags( use_flags ):
	if not use_flags:
		use_flags=""
	elif type(use_flags) in (list, tuple):
		 use_flags=" ".join(use_flags)
	use_flags="USE=%s" % use_flags
	return use_flags

def package_localinstall( package_path ):
	"""Install a package that is found in a particular filesystem path instead of
	using the availabler repositories."""
	package_manager=distro_check().get('pkg_mgr')
	if package_manager == 'apt-get':
		# JIM: One limitation to apt-get is that it does not install local packages, but
		# by dropping down to dpkg we lose the ability to automatically pick up
		# dependencies for the package being installed.  Long-term solution is the following:
		#
		#  1) TMPDEBS = mktmp -d localdebs.XXXXXXXX
		#  2) fabric.api.put(package_path, <<TMPDEBS>>
		#  3) See if package with same name exists to see what section it belongs in
		#  4) echo "<<pkgname>> high <<section_name or 'contrib'>>" > <<TMPDEBS>>/localdebs_overrides
		#  5) dpkg-scanpackages <<TMPDEBS>> localdebs_overrides | gzip > <<TMPDRBS>>/Packages.gz
		#  6) mv /etc/sources.list /etc/sources.list-localdebs && echo "deb file:/tmp <<TMPDEBS>>/" && cat /etc/sources.list-localdevs >> /etc/sources.list
		#  7) apt-get --yes update
		#  8) Install package(s)
		#  9) mv /etc/sources.list-localdevs /etc/sources.list
		#  10) rm -rf <<TMPDEBS>>
		#  11) apt-get --yes update
		sudo("(test -f %s && which dpkg >& /dev/null) && dpgk -i %s" % (package_path, package_path))
	elif package_manager == 'yum':
		sudo("test -f %s && yum -y localinstall --nogpg %s" % (package_path, package_path))

## JIM: Setting this as a multiargs command is a mistake.  If we are running ensure on multiple
## packages then we want to do them as a single yum/apt-get package in case there are
## circular dependencies in the installation; fewer calls to the remote box.  I think it was
## set up with a multiargs decorator because the original code is doing an unnecessary check
## to see if the package is already installed when the package installers will still work if
## you install an already-installed package.
@multiargs
def package_ensure( package, upgrade=False, db_update=False ):
	## JIM: Don't really need to check if it is installed, as the package_install command
	## will check this for us and not do unnecessary work.
	"""Ensures that a given package is installed, upgrading it if necessary and updating
	the package installer db if requested."""
	if run("dpkg -s %s 2>&1 | grep 'Status:' ; true" % package).find("installed") == -1:
		package_install(package)


## JIM: UPdate this to use "yum provides" for yum setups and to check to see if apt-file exists
## and use that if possible on apt setups.    Update the "command" arg so that we escape file glob chars like * & ?
def command_ensure( command, package=None ):
	"""Ensures that the given command is present, installs provided package if we can't
	otherwise figure out the package that provides the command."""
	if not command_check(command):
		distro_info = distro_check()
		package_manager = distro_info.get('pkg_mgr')
		if package_manager == 'apt-get' and 'apt-file' in distro_info.get('pkg_mgr_helper', []):
			package_manager == 'apt-file'
		if package_manager == 'yum':
			provides_output = run("yum -d 1 provides '%s' 2> /dev/null | egrep -v '^$|^ |^Matched|^Other|^Repo' | awk -F':' '{print $1}'" % (command))
			if len(provides_ouput) > 0:
				## XXX: finish parse
				pass
		elif package_manager == 'apt-file':
			provides_output = run("apt-file search %s" % (command))
			## JIM: Parse it
		elif package_manager == 'apt-get':
			if not package:
				package = command
		package_install(package)
	assert command_check(command), "Command was not installed, check for errors: %s" % (command)

def user_create( name, passwd=None, home=None, uid=None, gid=None, shell=None, uid_min=None, uid_max=None):
	"""Creates the user with the given name, optionally giving a specific password/home/uid/gid/shell."""
	options = ["-m"]
	if passwd: options.append("-p '%s'" % (passwd))
	if home: options.append("-d '%s'" % (home))
	if uid:  options.append("-u '%s'" % (uid))
	if gid:  options.append("-g '%s'" % (gid))
	if shell: options.append("-s '%s'" % (shell))
	if uid_min:  options.append("-K UID_MIN='%s'" % (uid_min))
	if uid_max:  options.append("-K UID_MAX='%s'" % (uid_max))
	sudo("useradd %s '%s'" % (" ".join(options), name))

def user_check( name ):
	"""Checks if there is a user defined with the given name, returning its information
	as a '{"name":<str>,"uid":<str>,"gid":<str>,"home":<str>,"shell":<str>}' or 'None' if
	the user does not exists."""
	d = run("cat /etc/passwd | egrep '^%s:' ; true" % (name))
	s = sudo("cat /etc/shadow | egrep '^%s:' | awk -F':' '{print $2}'")
	results = {}
	if d:
		d = d.split(":")
		results = dict(name=d[0],uid=d[2],gid=d[3],home=d[5],shell=d[6])
	if s:
		results['passwd']=s
	if results:
		return results
	else:
		return None

def user_ensure( name, passwd=None, home=None, uid=None, gid=None, shell=None):
	"""Ensures that the given users exists, optionally updating their passwd/home/uid/gid/shell."""
	d = user_check(name)
	if not d:
		user_create(name, passwd, home, uid, gid, shell)
	else:
		options=[]
		if passwd != None and d.get('passwd') != passwd:
			options.append("-p '%s'" % (passwd))
		if home != None and d.get("home") != home:
			options.append("-d '%s'" % (home))
		if uid  != None and d.get("uid") != uid:
			options.append("-u '%s'" % (uid))
		if gid  != None and d.get("gid") != gid:
			options.append("-g '%s'" % (gid))
		if shell != None and d.get("shell") != shell:
			options.append("-s '%s'" % (shell))
		if options:
			sudo("usermod %s '%s'" % (" ".join(options), name))

def group_create( name, gid=None ):
	"""Creates a group with the given name, and optionally given gid."""
	options = []
	if gid:  options.append("-g '%s'" % (gid))
	sudo("groupadd %s '%s'" % (" ".join(options), name))

def group_check( name ):
	"""Checks if there is a group defined with the given name, returning its information
	as a '{"name":<str>,"gid":<str>,"members":<list[str]>}' or 'None' if the group
	does not exists."""
	group_data = run("cat /etc/group | egrep '^%s:' ; true" % (name))
	if group_data:
		name,_,gid,members = group_data.split(":",4)
		return dict(name=name,gid=gid,members=tuple(m.strip() for m in members.split(",")))
	else:
		return None

def group_ensure( name, gid=None ):
	"""Ensures that the group with the given name (and optional gid) exists."""
	d = group_check(name)
	if not d:
		group_create(name, gid)
	else:
		if gid != None and d.get("gid") != gid:
			sudo("groupmod -g %s '%s'" % (gid, name))

def group_user_check( group, user ):
	"""Checks if the given user is a member of the given group. It will return 'False'
	if the group does not exist."""
	d = group_check(group)
	if d is None:
		return False
	else:
		return user in d["members"]

## JIM: This is doing a lot of round-trips using the funky file_write bits, should
#       be changed to make a local copy, update that copy, and push it back.
@multiargs
def group_user_add( group, user ):
	"""Adds the given user/list of users to the given group/groups."""
	assert group_check(group), "Group does not exist: %s" % (group)
	if not group_user_check(group, user):
		lines = []
		for line in file_read("/etc/group").split("\n"):
			if line.startswith(group + ":"):
				if line.strip().endswith(":"):
					line = line + user
				else:
					line = line + "," + user
			lines.append(line)
		text = "\n".join(lines)
		file_write("/etc/group", text)

def group_user_ensure( group, user):
	"""Ensure that a given user is a member of a given group."""
	d = group_check(group)
	if user not in d["members"]:
		group_user_add(group, user)

def ssh_keygen( user, keytype="dsa" ):
	"""Generates a pair of ssh keys in the user's home .ssh directory."""
	d = user_check(user)
	assert d, "User does not exist: %s" % (user)
	home = d["home"]
	if not file_exists(home + "/.ssh/id_%s.pub" % keytype):
		dir_ensure(home + "/.ssh", mode="0700", owner=user, group=user)
		run("ssh-keygen -q -t %s -f '%s/.ssh/id_%s' -N ''" % (home, keytype, keytype))
		file_attribs(home + "/.ssh/id_%s" % keytype,     owner=user, group=user)
		file_attribs(home + "/.ssh/id_%s.pub" % keytype, owner=user, group=user)

def ssh_authorize( user, key ):
	"""Adds the given key to the '.ssh/authorized_keys' for the given user."""
	d    = user_check(user)
	keyf = d["home"] + "/.ssh/authorized_keys"
	if file_exists(keyf):
		if file_read(keyf).find(key) == -1:
			file_append(keyf, key)
	else:
		file_write(keyf, key)

def remove_known_host(hostname, username=None):
	"""Remove hostname (and IP address of hostname if we can get it) from the
	local known_hosts file of the user running the command or a specified username."""
	if not username:
		known_hosts = os.path.expanduser("~/.ssh/known_hosts")
	else:
		known_hosts = os.path.expanduser("~%s/.ssh/known_hosts" % username)
	ipaddr_check=subprocess.Popen(["dig", hostname, "+short"], stdout=subprocess.PIPE)
        ipaddr=ipaddr_check.communicate()[0]
	if ipaddr[-1] == "\n":
		ipaddr=ipaddr[:-1]
	if os.path.exists(known_hosts):
		if len(ipaddr.split("."))==4:
			fabric.operations.local("sed -i '' '/%s/d;/%s/d' %s" % (hostname, ipaddr, known_hosts))
		else:
			fabric.operations.local("sed -i '' '/%s/d' %s" % (hostname, known_hosts))

def service_stop(name, no_start=False):
	"""Stop a service, clearing its runlevels if requested."""
	if distro_check().get("distro") in ("debian", "ubuntu"):
		sudo("stop %s >& /dev/null; true" % name)
		if no_start:
			sudo("update-rc.d -f %s remove ; true" % name)
	elif distro_check().get("distro") in ("redhat", "fedora"):
		sudo("service %s stop >& /dev/null ; true" % name)
		if no_start:
			sudo("chkconfig %s off ; true" % name)
	elif distro_check().get("distro") in ("gentoo"):
		sudo("stop %s >& /dev/null ; true" % name)
		if no_start:
			sudo("rc-update del %s default ; true" % name)
	
def service_ensure( name, runlevels=None, restart=False):
	"""Ensure that a named service is running (or restart) and set runlevels."""
	# Using a "stop then start" pattern instead of just calling restart because
	# the latter may return a non-zero exit if the service was not running in the
	# first place, and we really only care about getting the service running.
	if distro_check().get("distro") in ("debian", "ubuntu"):
		if restart:
			service_stop(name)
		sudo("start %s" % name)
		if runlevels: # Upstart is not as fine-grained as chkconfig, so we use "defaults"
			sudo("update-rc.d %s defaults" % (name))
	elif distro_check().get("distro") in ("redhat", "fedora"):
		if restart:
			service_stop(name)
		sudo("service %s start" % name)
		if runlevels:
			sudo("chkconfig --levels %s %s on" % (runlevels, name))
	elif distro_check().get("distro") in ("gentoo"):
		if restart:
			service_stop(name)
		sudo("start %s" % name)
		if runlevels: # Upstart is not as fine-grained as chkconfig, so we use "defaults"
			sudo("rc-update add %s default" % (name))	


# JIM: still missing --
#        - lean a bit more on fabric.contrib (esp. fabric.contrib.file for things like file exists, sed,
#          templating, etc.)
#        - kernel params and sysctl checking/config
#        - network config and net devices
#        - the file_write function seems a bit strange; why not use fabric.apt.get() to pull a copy,
#          put it into a tmpfile, manipulate the tmpfile, and the fabric.api.put() it back?  If we
#          are concerned about safety we can put the file to a remote tmpfile and then mv it into
#          place.  If this is done, use "find <<filename>> -prune -printf '%m %U %G\n'" to get the
#          perms, owner, and group so that we can reset them afterwards.
#        - bsd compatibility (ports system, osx support, bsd find does not have printf so get_fs_attr
#          would need to call stat instead, etc.)
#        - user_create/user_ensure should interpret a None password as the user needing to be set to !! as
#          the encrypted password
#        - relplace all of the various platform-specific if clauses with templates.  Define a command
#          dict that has the various commands as templates and then create the arg dicts from the function
#          params and env and then run the a string template substitution.  Need to convert None args to
#          an empty string (perhaps creating a defaultdict for the params that returns '' if the key is
#          None but still raising a KeyError is we need a param and it is not there)
#        - add a groupdel and userdel bit (with ability to specify login.defs vars as method args)
#        - fix service_stop & service_ensure to deal better with services that do not exist (do not complain
#          about trying to stop them but do complain about trying to start them, etc.)

## JIM: package installs need to go back and do a check to make sure the package is installed (should upgrade
## check to make sure a newer rev is installed?) and return proper .success or .failure.  We can't just
## blindly trust that things will work...

# EOF - vim: ts=4 sw=4 noet
