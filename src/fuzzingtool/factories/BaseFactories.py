from abc import ABC, abstractmethod

class BaseHttpFactory(ABC):
    @staticmethod
    @abstractmethod
    def requestCreator(requestType, url, **kwargs):
        pass

class BasePluginFactory(ABC):
    @staticmethod
    @abstractmethod
    def classCreator(name, category):
        """Get the import for the plugin

        @type name: str
        @param name: The plugin to be searched for
        @type category: str
        @param category: The category of the searched plugin
        @returns import: The import of the searched plugin
        """
        pass

    @staticmethod
    @abstractmethod
    def objectCreator(name, category, params):
        pass