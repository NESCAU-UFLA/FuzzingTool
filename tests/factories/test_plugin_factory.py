import unittest
from unittest.mock import Mock, patch

from fuzzingtool.factories.plugin_factory import PluginFactory
from fuzzingtool.core.plugins import scanners, Grep


class TestPluginFactory(unittest.TestCase):
    @patch("fuzzingtool.factories.plugin_factory.getattr")
    @patch("fuzzingtool.factories.plugin_factory.import_module")
    def test_class_creator(self,
                           mock_import_module: Mock,
                           mock_getattr: Mock):
        test_plugin = "Grep"
        test_category = "scanners"
        test_module = scanners
        mock_import_module.return_value = test_module
        mock_getattr.return_value = Grep
        returned_data = PluginFactory.class_creator(test_plugin, test_category)
        mock_import_module.assert_called_once_with(
            f"fuzzingtool.core.plugins.{test_category}",
            package=test_plugin
        )
        mock_getattr.assert_called_once_with(test_module, test_plugin)
        self.assertIsInstance(returned_data, type(Grep))
        self.assertEqual(returned_data, Grep)
