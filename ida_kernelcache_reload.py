#
# ida_kernelcache.py
# Brandon Azad
#
# A script to import the ida_kernelcache module into IDA, reloading all the necessary internal
# modules.
#

import sys
modules = list(sys.modules.keys())
for mod in modules:
    if 'ida_kernelcache' in mod:
        del sys.modules[mod]

import ida_kernelcache
import ida_kernelcache as kc
