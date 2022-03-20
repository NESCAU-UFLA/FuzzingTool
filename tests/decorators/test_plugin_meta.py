import unittest

from src.fuzzingtool.decorators.plugin_meta import plugin_meta
from src.fuzzingtool.exceptions import MetadataException


class TestPluginMeta(unittest.TestCase):
    def test_mandatory_meta_without_any_meta(self):
        with self.assertRaises(MetadataException) as e:
            @plugin_meta
            class TestPlugin:
                pass
        self.assertEqual(str(e.exception), "Metadata __author__ not specified on plugin TestPlugin")

    def test_mandatory_meta_without_version(self):
        with self.assertRaises(MetadataException) as e:
            @plugin_meta
            class TestPlugin:
                __author__ = "Test Author"
                __params__ = {}
                __desc__ = "Test Description"
                __type__ = "Test Type"
        self.assertEqual(str(e.exception), "Metadata __version__ not specified on plugin TestPlugin")

    def test_blank_meta_on_author(self):
        with self.assertRaises(MetadataException) as e:
            @plugin_meta
            class TestPlugin:
                __author__ = ''
                __params__ = {}
                __desc__ = "Test Description"
                __type__ = "Test Type"
                __version__ = "Test Version"
        self.assertEqual(str(e.exception), "Author cannot be empty on plugin TestPlugin")

    def test_blank_meta_on_desc(self):
        with self.assertRaises(MetadataException) as e:
            @plugin_meta
            class TestPlugin:
                __author__ = "Test Author"
                __params__ = {}
                __desc__ = ''
                __type__ = "Test Type"
                __version__ = "Test Version"
        self.assertEqual(str(e.exception), "Description cannot be blank on plugin TestPlugin")

    def test_blank_meta_on_version(self):
        with self.assertRaises(MetadataException) as e:
            @plugin_meta
            class TestPlugin:
                __author__ = "Test Author"
                __params__ = {}
                __desc__ = "Test Description"
                __type__ = "Test Type"
                __version__ = ''
        self.assertEqual(str(e.exception), "Version cannot be blank on plugin TestPlugin")

    def test_param_meta_is_not_dict(self):
        with self.assertRaises(MetadataException) as e:
            @plugin_meta
            class TestPlugin:
                __author__ = "TestAuthor"
                __params__ = "Test Param"
                __desc__ = "Test Description"
                __type__ = "Test Type"
                __version__ = "Test Version"
        self.assertEqual(str(e.exception), "The parameters must be a dictionary on plugin TestPlugin")

    def test_param_meta_without_key_type(self):
        with self.assertRaises(MetadataException) as e:
            @plugin_meta
            class TestPlugin:
                __author__ = "Test Author"
                __params__ = {
                    'metavar': "TEST_METAVAR"
                }
                __desc__ = "Test Description"
                __type__ = "Test Type"
                __version__ = "Test Version"
        self.assertEqual(str(e.exception), "Key type must be in parameters dict on plugin TestPlugin")

    def test_param_meta_without_value_type(self):
        with self.assertRaises(MetadataException) as e:
            @plugin_meta
            class TestPlugin:
                __author__ = "Test Author"
                __params__ = {
                    'metavar': "TEST_METAVAR",
                    'type': None
                }
                __desc__ = "Test Description"
                __type__ = "Test Type"
                __version__ = "Test Version"
        self.assertEqual(str(e.exception), "Value of type cannot be empty in parameters dict on plugin TestPlugin")

    def test_param_meta_list_without_separator(self):
        with self.assertRaises(MetadataException) as e:
            @plugin_meta
            class TestPlugin:
                __author__ = "Test Author"
                __params__ = {
                    'metavar': "TEST_METAVAR",
                    'type': list
                }
                __desc__ = "Test Description"
                __type__ = "Test Type"
                __version__ = "Test Version"
        self.assertEqual(str(e.exception), "The key 'cli_list_separator' must be present when parameter type is list on plugin TestPlugin")

    def test_param_meta_list_with_blank_separator(self):
        with self.assertRaises(MetadataException) as e:
            @plugin_meta
            class TestPlugin:
                __author__ = "Test Author"
                __params__ = {
                    'metavar': "TEST_METAVAR",
                    'type': list,
                    'cli_list_separator': ''
                }
                __desc__ = "Test Description"
                __type__ = "Test Type"
                __version__ = "Test Version"
        self.assertEqual(str(e.exception), "Value of 'cli_list_separator' cannot be blank on TestPlugin")
