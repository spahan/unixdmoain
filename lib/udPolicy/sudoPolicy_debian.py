# coding: utf-8
"""
This policy manages sudoers
This is the subclass for Debian systems which use the "sudo" group
"""

from UniDomain.udPolicy.sudoPolicy import sudoPolicy as base


class sudoPolicy(base):
    """ the Debian sudo Policy just overwrites the group name. """
    #which group has sudo admin rights.
    sudo_group = 'sudo'
