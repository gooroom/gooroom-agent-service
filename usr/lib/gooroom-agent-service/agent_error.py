#! /usr/bin/env python3

#-----------------------------------------------------------------------
class AgentError(Exception):
    """
    Agent Custiom Exception
    """

    def __init__(self,*args,**kwargs):
        Exception.__init__(self,*args,**kwargs)

class AgentHttpStatusError(Exception):
    """
    http status != 200
    """

    def __init__(self,*args,**kwargs):
        Exception.__init__(self,*args,**kwargs)
