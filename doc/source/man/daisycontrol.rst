==============
daisy-control
==============

--------------------------------------
daisy daemon start/stop/reload helper
--------------------------------------

:Author: daisy@lists.launchpad.net
:Date:   2014-01-16
:Copyright: OpenStack LLC
:Version: 2014.1
:Manual section: 1
:Manual group: cloud computing

SYNOPSIS
========

  daisy-control [options] <SERVER> <COMMAND> [CONFPATH]

Where <SERVER> is one of:

    all, api, daisy-api, registry, daisy-registry, scrubber, daisy-scrubber

And command is one of:

    start, status, stop, shutdown, restart, reload, force-reload

And CONFPATH is the optional configuration file to use.

OPTIONS
========

  **General Options**

  .. include:: general_options.rst

  **--pid-file=PATH**
        File to use as pid file. Default:
        /var/run/daisy/$server.pid

  **--await-child DELAY**
        Period to wait for service death in order to report
        exit code (default is to not wait at all)

  **--capture-output**
        Capture stdout/err in syslog instead of discarding

  **--nocapture-output**
        The inverse of --capture-output

  **--norespawn**
        The inverse of --respawn

  **--respawn**
        Restart service on unexpected death

  .. include:: footer.rst
