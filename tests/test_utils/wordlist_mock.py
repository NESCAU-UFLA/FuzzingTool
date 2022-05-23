from src.fuzzingtool.core.bases.base_wordlist import BaseWordlist
from src.fuzzingtool.exceptions import WordlistCreationError, BuildWordlistFails


class WordlistMock(BaseWordlist):
    def __init__(self, test_arg: str):
        if not test_arg:
            raise WordlistCreationError()
        self.test_arg = test_arg
        super().__init__()

    def _build(self):
        if self.test_arg == '0':
            raise BuildWordlistFails()
        return ["test1", "test2"]
