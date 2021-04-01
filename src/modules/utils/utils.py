def getIndexesToParse(content: str, searchFor: str = '$'):
    """Gets the indexes of the searched substring into a string content
    
    @type content: str
    @param content: The parameter content
    @type searchFor: str
    @param searchFor: The substring to be searched indexes on the given content
    @returns list: The positions indexes of the searched substring.
                   Returns an empty list if the tests'll not occur
    """
    return [i for i, char in enumerate(content) if char == searchFor]

def getCustomPackages(module: str):
    """Gets the custom packages

    @type module: str
    @param module: The module to search for the custom packages
    @returns list: The list with the custom packages filenames
    """
    from os import walk
    _, _, customPackages = next(walk(f"./modules/core/{module}/custom/"))
    if '__init__.py' in customPackages:
        customPackages.remove('__init__.py')
    return [packageFile.split('.')[0] for packageFile in customPackages]

def importCustomPackage(module: str, package: str):
    """Get the import for the custom package

    @type module: str
    @param module: The module of the custom package
    @type package: str
    @param package: The package to be searched for
    @returns import: The import of the searched package
    """
    from importlib import import_module
    try:
        customImported = import_module(
            f".modules.core.{module}.custom.{package}",
            package=f"{package}"
        )
    except:
        customImported = import_module(
            f"modules.core.{module}.custom.{package}",
            package=f"{package}"
        )
    return getattr(customImported, package)