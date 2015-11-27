# coding: utf-8
"""
user policy implementation for debian. same as other Linux, just use -N instead -n....
"""
from UniDomain.udPolicy.userPolicy_Linux import userPolicy as base

class  userPolicy(base):
    do_not_create_user_group_option = '-N'
