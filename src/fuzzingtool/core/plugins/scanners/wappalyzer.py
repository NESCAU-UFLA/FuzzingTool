# Copyright (c) 2020 - present Vitor Oriel <https://github.com/VitorOriel>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import warnings

import Wappalyzer as WP

from ...bases.base_plugin import Plugin
from ...bases.base_scanner import BaseScanner
from ....objects.result import Result
from ....decorators.plugin_meta import plugin_meta


@plugin_meta
class Wappalyzer(BaseScanner, Plugin):
    __author__ = ("Vitor Oriel",)
    __params__ = {}
    __desc__ = "Lookup for technologies on a web page during discovery scan"
    __type__ = None
    __version__ = "0.1"

    def __init__(self):
        warnings.filterwarnings("ignore", category=UserWarning)
        BaseScanner.__init__(self)

    def scan(self, result: Result) -> bool:
        return True

    def _process(self, result: Result) -> None:
        wp_technologies_dict = WP.Wappalyzer.latest().analyze_with_versions_and_categories(
            webpage=WP.WebPage.new_from_response(result.history.response)
        )
        technologies = []
        for key, value in wp_technologies_dict.items():
            version = ''
            if value['versions']:
                version = ' v' + ' | v'.join(value['versions'])
            technologies.append(f"{key}{version}")
        self.get_self_res(result).data['technologies'] = technologies
