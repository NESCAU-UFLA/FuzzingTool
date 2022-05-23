from unittest import TestCase

from src.fuzzingtool.utils.fuzz_mark import FuzzMark


class FuzzMarkTestCase(TestCase):
    def setUp(self):
        FuzzMark.all_marks.add(FuzzMark.BASE_MARK)

    def tearDown(self):
        FuzzMark.all_marks = set()
        FuzzMark.recursion_mark_index = -1
