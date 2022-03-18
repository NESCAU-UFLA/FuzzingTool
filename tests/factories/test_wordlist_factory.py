import unittest
from unittest.mock import Mock, patch

from src.fuzzingtool.factories.wordlist_factory import WordlistFactory
from src.fuzzingtool.conn.requesters import Requester, SubdomainRequester
from src.fuzzingtool.core.defaults.wordlists import ListWordlist, FileWordlist
from src.fuzzingtool.core.plugins.wordlists import Robots, CrtSh
from src.fuzzingtool.exceptions.main_exceptions import WordlistCreationError
from src.fuzzingtool.exceptions.plugin_exceptions import InvalidPlugin, PluginCreationError
from src.fuzzingtool.utils.consts import FUZZING_MARK


class TestWordlistFactory(unittest.TestCase):
    @patch("src.fuzzingtool.factories.wordlist_factory.PluginFactory.class_creator")
    def test_creator_with_list(self, mock_plugin_class_creator: Mock):
        test_name = "[1,2,3,4,5]"
        mock_plugin_class_creator.side_effect = InvalidPlugin
        returned_data = WordlistFactory.creator(test_name, '', None)
        mock_plugin_class_creator.assert_called_once_with(test_name, "wordlists")
        self.assertIsInstance(returned_data, ListWordlist)
    
    @patch("src.fuzzingtool.factories.wordlist_factory.PluginFactory.class_creator")
    def test_creator_with_file(self, mock_plugin_class_creator: Mock):
        test_name = "/home/test_wordlists/wordlist.txt"
        mock_plugin_class_creator.side_effect = InvalidPlugin
        returned_data = WordlistFactory.creator(test_name, '', None)
        mock_plugin_class_creator.assert_called_once_with(test_name, "wordlists")
        self.assertIsInstance(returned_data, FileWordlist)

    @patch("src.fuzzingtool.factories.wordlist_factory.PluginFactory.object_creator")
    @patch("src.fuzzingtool.factories.wordlist_factory.PluginFactory.class_creator")
    def test_creator_with_plugin_and_params(
        self,
        mock_plugin_class_creator: Mock,
        mock_plugin_object_creator: Mock
    ):
        test_name = "Robots"
        test_params = "https://test-url.com/"
        mock_plugin_class_creator.return_value = Robots
        mock_plugin_object_creator.return_value = Robots(test_params)
        returned_data = WordlistFactory.creator(test_name, test_params, None)
        mock_plugin_class_creator.assert_called_with(test_name, "wordlists")
        mock_plugin_object_creator.assert_called_once_with(test_name, "wordlists", test_params)
        self.assertIsInstance(returned_data, Robots)

    @patch("src.fuzzingtool.factories.wordlist_factory.Requester.get_url")
    @patch("src.fuzzingtool.factories.wordlist_factory.get_pure_url")
    @patch("src.fuzzingtool.factories.wordlist_factory.PluginFactory.object_creator")
    @patch("src.fuzzingtool.factories.wordlist_factory.PluginFactory.class_creator")
    def test_creator_with_path_fuzzing_plugin_and_requester(
        self,
        mock_plugin_class_creator: Mock,
        mock_plugin_object_creator: Mock,
        mock_get_pure_url: Mock,
        mock_requester_get_url: Mock
    ):
        test_name = "Robots"
        test_requester_url = f"https://test-url.com/{FUZZING_MARK}"
        test_requester = Requester(test_requester_url)
        test_pure_url = "https://test-url.com/"
        mock_plugin_class_creator.return_value = Robots
        mock_plugin_object_creator.return_value = Robots(test_pure_url)
        mock_get_pure_url.return_value = test_pure_url
        mock_requester_get_url.return_value = test_requester_url
        returned_data = WordlistFactory.creator(test_name, '', test_requester)
        mock_plugin_class_creator.assert_called_with(test_name, "wordlists")
        mock_plugin_object_creator.assert_called_once_with(test_name, "wordlists", test_pure_url)
        mock_get_pure_url.assert_called_once_with(test_requester_url)
        mock_requester_get_url.assert_called_once()
        self.assertIsInstance(returned_data, Robots)

    @patch("src.fuzzingtool.factories.wordlist_factory.Requester.get_url")
    @patch("src.fuzzingtool.factories.wordlist_factory.get_pure_url")
    @patch("src.fuzzingtool.factories.wordlist_factory.get_parsed_url")
    @patch("src.fuzzingtool.factories.wordlist_factory.PluginFactory.object_creator")
    @patch("src.fuzzingtool.factories.wordlist_factory.PluginFactory.class_creator")
    def test_creator_with_subdomain_fuzzing_plugin_and_requester(
        self,
        mock_plugin_class_creator: Mock,
        mock_plugin_object_creator: Mock,
        mock_get_parsed_url: Mock,
        mock_get_pure_url: Mock,
        mock_requester_get_url: Mock
    ):
        test_name = "CrtSh"
        test_requester_url = f"https://{FUZZING_MARK}.test-url.com/"
        test_requester = SubdomainRequester(test_requester_url)
        test_pure_url = "https://test-url.com/"
        test_host = "test-url.com"
        mock_plugin_class_creator.return_value = CrtSh
        mock_plugin_object_creator.return_value = CrtSh(test_host)
        mock_get_parsed_url.return_value.hostname = test_host
        mock_get_pure_url.return_value = test_pure_url
        mock_requester_get_url.return_value = test_requester_url
        returned_data = WordlistFactory.creator(test_name, '', test_requester)
        mock_plugin_class_creator.assert_called_with(test_name, "wordlists")
        mock_plugin_object_creator.assert_called_once_with(test_name, "wordlists", test_host)
        mock_get_parsed_url.assert_called_once_with(test_pure_url)
        mock_get_pure_url.assert_called_once_with(test_requester_url)
        mock_requester_get_url.assert_called_once()
        self.assertIsInstance(returned_data, CrtSh)

    @patch("src.fuzzingtool.factories.wordlist_factory.PluginFactory.object_creator")
    @patch("src.fuzzingtool.factories.wordlist_factory.PluginFactory.class_creator")
    def test_creator_with_raise_plugin_exception(
        self,
        mock_plugin_class_creator: Mock,
        mock_plugin_object_creator: Mock
    ):
        test_name = "Robots"
        test_params = "https://test-url.com/"
        mock_plugin_class_creator.return_value = Robots
        mock_plugin_object_creator.side_effect = PluginCreationError
        with self.assertRaises(WordlistCreationError):
            WordlistFactory.creator(test_name, test_params, None)
