import unittest
from unittest.mock import Mock, patch

from src.fuzzingtool.utils.consts import PluginCategory
from src.fuzzingtool.factories.plugin_factory import PluginFactory
from src.fuzzingtool.core.plugins import scanners, Grep, Reflected
from src.fuzzingtool.exceptions.plugin_exceptions import InvalidPlugin, InvalidPluginCategory, PluginCreationError


class TestPluginFactory(unittest.TestCase):
    def test_get_plugins_from_category(self):
        test_category = PluginCategory.scanner
        return_expected = [Grep]
        with patch.dict(scanners.__dict__, {'Grep': Grep, 'Test': None}, clear=True):
            returned_data = PluginFactory.get_plugins_from_category(test_category)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)

    def test_get_plugins_from_category_with_invalid_category(self):
        test_category = "test_categoty"
        with self.assertRaises(InvalidPluginCategory):
            PluginFactory.get_plugins_from_category(test_category)

    @patch("src.fuzzingtool.factories.plugin_factory.getattr")
    @patch("src.fuzzingtool.factories.plugin_factory.import_module")
    def test_class_creator(self,
                           mock_import_module: Mock,
                           mock_getattr: Mock):
        test_plugin = "Grep"
        test_category = PluginCategory.scanner
        test_module = scanners
        return_expected = Grep
        mock_import_module.return_value = test_module
        mock_getattr.return_value = return_expected
        returned_data = PluginFactory.class_creator(test_category, test_plugin)
        mock_import_module.assert_called_once_with(
            f"fuzzingtool.core.plugins.{test_category}",
            package=test_plugin
        )
        mock_getattr.assert_called_once_with(test_module, test_plugin)
        self.assertIsInstance(returned_data, type(return_expected))
        self.assertEqual(returned_data, return_expected)

    @patch("src.fuzzingtool.factories.plugin_factory.import_module")
    def test_class_creator_with_invalid_plugin(self, mock_import_module: Mock):
        test_plugin = "InvalidPluginTest"
        test_category = PluginCategory.scanner
        mock_import_module.return_value = scanners
        with self.assertRaises(InvalidPlugin):
            PluginFactory.class_creator(test_category, test_plugin)

    @patch("src.fuzzingtool.factories.plugin_factory.PluginFactory.class_creator")
    def test_object_creator_with_invalid_plugin(self, mock_class_creator: Mock):
        test_plugin = "InvalidPluginTest"
        test_category = PluginCategory.scanner
        test_params = ''
        mock_class_creator.side_effect = InvalidPlugin
        with self.assertRaises(PluginCreationError):
            PluginFactory.object_creator(test_category, test_plugin, test_params)

    @patch("src.fuzzingtool.factories.plugin_factory.PluginFactory.class_creator")
    def test_object_creator_with_params(self, mock_class_creator: Mock):
        test_name = "Grep"
        test_category = PluginCategory.scanner
        test_params = "email"
        mock_class_creator.return_value = Grep
        returned_data = PluginFactory.object_creator(test_category, test_name, test_params)
        self.assertIsInstance(returned_data, Grep)

    @patch("src.fuzzingtool.factories.plugin_factory.PluginFactory.class_creator")
    def test_object_creator_without_params(self, mock_class_creator: Mock):
        test_name = "Reflected"
        test_category = PluginCategory.scanner
        test_params = ''  # No need to have params on constructor
        mock_class_creator.return_value = Reflected
        returned_data = PluginFactory.object_creator(test_category, test_name, test_params)
        self.assertIsInstance(returned_data, Reflected)

    @patch("src.fuzzingtool.factories.plugin_factory.PluginFactory.class_creator")
    def test_object_creator_with_blank_params(self, mock_class_creator: Mock):
        test_name = "Grep"
        test_category = PluginCategory.scanner
        test_params = ''
        mock_class_creator.return_value = Grep
        with self.assertRaises(PluginCreationError):
            PluginFactory.object_creator(test_category, test_name, test_params)

    @patch("src.fuzzingtool.factories.plugin_factory.PluginFactory.class_creator")
    def test_object_creator_with_invalid_params(self, mock_class_creator: Mock):
        test_name = "Grep"
        test_category = PluginCategory.scanner
        test_params = "\\"  # Invalid regex
        mock_class_creator.return_value = Grep
        with self.assertRaises(PluginCreationError):
            PluginFactory.object_creator(test_category, test_name, test_params)
