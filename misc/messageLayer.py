#!/usr/bin/python

import sys
import os.path
sys.path.append("~/isoImages/onf2013/build/bindings/ofp")
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
print(sys.path)
import flog

def get_ofp_version(ver):
    """Returns the OFP module that implements the given version."""
    if ver == 1:
       import flog_ofp_v1_0
       return flog_ofp_v1_0
    elif ver == 2:
       import flog_ofp_v1_1
       return flog_ofp_v1_1
    else:
       raise "Unsupported protocol version"

if __name__ == '__main__':
        
        try:
            ver = get_ofp_version(1)
            print "Version was ", ver
        except KeyboardInterrupt:
            print "Ctrl C - Stopping server"
            sys.exit(1)
