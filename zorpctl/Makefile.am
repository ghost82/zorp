#sbin_SCRIPTS = zorpctl

sysconf_DATA = instances.conf.sample zorpctl.conf

pkgdatadir = @ZORPCTL_PYTHON_DIR@

pkgdata_DATA = __init__.py   \
	CommandResults.py    \
	Instances.py         \
	PluginAlgorithms.py  \
	ProcessAlgorithms.py \
	SZIGMessages.py      \
	szig.py              \
	UInterface.py        \
	utils.py             \
	ZorpctlConf.py

EXTRA_DIST = $(pkgdata_DATA) $(sysconf_DATA) $(sbin_SCRIPTS)
