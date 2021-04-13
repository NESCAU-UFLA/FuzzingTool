# Contributing
Before contribute to the FuzzingTool project, please read our [Code of Conduct](https://github.com/NESCAU-UFLA/FuzzingTool/blob/master/.github/CODE_OF_CONDUCT.md).

## Bug Report
Read our document [BUG_REPORT.md](https://github.com/NESCAU-UFLA/FuzzingTool/blob/master/.github/ISSUE_TEMPLATE/BUG_REPORT.md) to check the issue template for bug reporting.

## Feature Request
Read our document [FEATURE_REQUEST.md](https://github.com/NESCAU-UFLA/FuzzingTool/blob/master/.github/ISSUE_TEMPLATE/FEATURE_REQUEST.md) to check the issue template for request a feature.

## Code contributing
You can contribute for FuzzingTool project with:
 * Code refatoring (better encapsulation, for example);
 * Implement new features;
 * Bugfixes;

### Code guidelines
If you want to code contribute for FuzzingTool, follow this guideline:
 * Variable names must be cohesive with the context. Do not drop variable names like `x, y, z`;
 * Every function or method must have a description about it on comments, with the parameters and the return (if it has). An exception is for the methods that already have their meanings builded in (like class constructors if no parameters are passed, and destructors), and overriding methods. See this example:
 ```py
def concatenate(paramOne: int, paramTwo: str):
    """Concatenates the first parameter into the second parameter

    @type paramOne: int
    @param paramOne: An example of integer parameter
    @type paramTwo: str
    @param paramTwo: An example of string parameter
    @returns str: The concatenation of the given parameters
    """
    return f"{str(paramOne)}{paramTwo}"
 ```
 * Every class attribute that are being initialized on the constructor, must have an description. If you want to include a description for attributes that are outside of the constructor, just put inside the respectived method that are being called. For example:
 ```py
class Foo:
    """Class that handles with Foo

    Attributes:
        counter: A counter for the each Foo's method call
        varOne: A example variable to store the value for the first parameter
        varTwo: A example variable to store the value for the second parameter
    """
    def __init__(self, numOne: int, numTwo: int):
        """Class constructor

        @type numOne: int
        @param numOne: The first parameter of the example
        @type numTwo: int
        @param numTwo: The second parameter of the example
        """
        # No need to follow protected (_) or private (__) prefixes on attribute names
        self.counter = 0
        self._varOne = numOne
        self.__varTwo = numTwo
    
    def sum(self):
        """Make the sum between attributes and store the result into a buffer
        
        Attribute:
            sumBuffer: A buffer to store the sum results
        """
        self.counter += 1
        self.sumBuffer = self._varOne + self.__varTwo
 ```
 * Do not leave blank lines when inside a function or method, just to separate between each class, method or function.