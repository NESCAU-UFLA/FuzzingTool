import sys
from unittest.mock import patch


def mock_sys_args(sys_args):
    sys_args = ['FuzzingTool'] + sys_args

    def func_wrapper(func):
        def wrapper(cls):
            with patch.object(sys, 'argv', sys_args):
                return func(cls)
        return wrapper
    return func_wrapper
