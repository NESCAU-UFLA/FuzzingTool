from .BaseFactories import BasePluginFactory
from ..utils.utils import getPluginNamesFromCategory
from ..core.dictionaries import *
from ..core.encoders import *
from ..core.scanners import *
from ..exceptions.MainExceptions import InvalidPluginName, MissingParameter

from importlib import import_module

class PluginFactory(BasePluginFactory):
    def classCreator(name, category):
        Plugin = import_module(
            f"fuzzingtool.core.{category}.custom.{name}",
            package=name
        )
        return getattr(Plugin, name)

    def objectCreator(name, category, params = ''):
        if name in getPluginNamesFromCategory(category):
            Plugin = PluginFactory.classCreator(name, category)
            if not Plugin.__params__:
                return Plugin()
            else:
                try:
                    return Plugin(params)
                except MissingParameter as e:
                    raise Exception(f"Plugin {name} missing parameter: {str(e)}")
                except Exception as e:
                    raise Exception(f"Bad plugin {name} argument format: {str(e)}")
        else:
            raise InvalidPluginName(f"Plugin {name} does not exists")