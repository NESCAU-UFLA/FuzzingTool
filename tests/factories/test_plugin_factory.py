import unittest
from unittest.mock import Mock, patch

from fuzzingtool.factories.plugin_factory import PluginFactory
from fuzzingtool.core.plugins import scanners, Grep
from fuzzingtool.exceptions.plugin_exceptions import InvalidPlugin, InvalidPluginCategory


class TestPluginFactory(unittest.TestCase):
    def test_get_plugins_from_category(self):
        test_category = "scanners"
        return_expected = [Grep]
        with patch.dict(scanners.__dict__, {'Grep': Grep, 'Test': None}, clear=True) as _:
            returned_data = PluginFactory.get_plugins_from_category(test_category)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)

    def test_get_plugins_from_category_with_invalid_category(self):
        test_category = "test_categoty"
        with self.assertRaises(InvalidPluginCategory):
            PluginFactory.get_plugins_from_category(test_category)

    @patch("fuzzingtool.factories.plugin_factory.getattr")
    @patch("fuzzingtool.factories.plugin_factory.import_module")
    def test_class_creator(self,
                           mock_import_module: Mock,
                           mock_getattr: Mock):
        test_plugin = "Grep"
        test_category = "scanners"
        test_module = scanners
        return_expected = Grep
        mock_import_module.return_value = test_module
        mock_getattr.return_value = return_expected
        returned_data = PluginFactory.class_creator(test_plugin, test_category)
        mock_import_module.assert_called_once_with(
            f"fuzzingtool.core.plugins.{test_category}",
            package=test_plugin
        )
        mock_getattr.assert_called_once_with(test_module, test_plugin)
        self.assertIsInstance(returned_data, type(return_expected))
        self.assertEqual(returned_data, return_expected)

    @patch("fuzzingtool.factories.plugin_factory.import_module")
    def test_class_creator_with_invalid_plugin(self, mock_import_module: Mock):
        test_plugin = "InvalidPluginTest"
        test_category = "scanners"
        mock_import_module.return_value = scanners
        with self.assertRaises(InvalidPlugin):
            PluginFactory.class_creator(test_plugin, test_category)

    @patch("fuzzingtool.factories.plugin_factory.PluginFactory.class_creator")
    def test_object_creator(self, mock_class_creator: Mock):
        test_name = "Grep"
        test_category = "scanners"
        test_params = "email"
        mock_class_creator.return_value = Grep
        returned_data = PluginFactory.object_creator(test_name, test_category, test_params)
        self.assertIsInstance(returned_data, Grep)
