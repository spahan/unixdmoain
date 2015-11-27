# coding: utf-8
"""
This policy manages sudoers
This is the subclass for Ubuntu systems which use the "admin" group
"""

from UniDomain.udPolicy.sudoPolicy import sudoPolicy as base


class sudoPolicy(base):
    """ the Ubuntu sudo Policy just overwrites the group name. """
    #which group has sudo admin rights.
    sudo_group = 'admin'
