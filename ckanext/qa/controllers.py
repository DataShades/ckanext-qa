"""
Link Checker Controller - DEPRECATED

This controller exposes only one action: check_link
"""

import ckanext.qa.utils as utils

class LinkCheckerController(BaseController):

    def check_link(self):
        return utils.check_link_route()
