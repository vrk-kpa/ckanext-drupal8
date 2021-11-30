from flask import Blueprint
from ckan.plugins import toolkit


drupal8 = Blueprint('drupal8_blueprint', __name__)


def get_blueprints():
    return [drupal8]


@drupal8.route('/drupal8_unauthorized', methods=['GET'])
def unauthorized():
    toolkit.c.code = 401
    toolkit.c.content = toolkit._('You are not authorized to do this')
    return toolkit.render('error_document_template.html')
