# -*- coding: utf-8 -*-
from flask import Blueprint
import ckanext.qa.utils as utils


def get_blueprints():
    return [qa]


qa = Blueprint('qa', __name__)


        # map.connect('qa_resource_checklink', '',
@qa.route('/qa/link_checker')
def check_link():
    return utils.check_link_route()
