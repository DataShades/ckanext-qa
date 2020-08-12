import json
import mimetypes
import posixpath
import urllib
import logging
from six.moves.urllib.parse import urlparse

from sqlalchemy import or_

import ckan.plugins as p
import ckan.plugins.toolkit as tk
from ckan.lib.helpers import parse_rfc_2822_date
from ckan.lib import helpers as ckan_helpers

from ckanext.archiver.tasks import link_checker, LinkCheckerError

log = logging.getLogger(__name__)


def init_db():
    import ckan.model as model
    from ckanext.qa.model import init_tables
    init_tables(model.meta.engine)


def update(args, queue):
    from ckan import model
    from ckanext.qa import lib
    packages = []
    resources = []
    if args:
        for arg in args:
            # try arg as a group id/name
            group = model.Group.get(arg)
            if group and group.is_organization:
                # group.packages() is unreliable for an organization -
                # member objects are not definitive whereas owner_org, so
                # get packages using owner_org
                query = model.Session.query(model.Package)\
                    .filter(
                        or_(model.Package.state == 'active',
                            model.Package.state == 'pending'))\
                    .filter_by(owner_org=group.id)
                packages.extend(query.all())
                if not queue:
                    queue = 'bulk'
                continue
            elif group:
                packages.extend(group.packages())
                if not queue:
                    queue = 'bulk'
                continue
            # try arg as a package id/name
            pkg = model.Package.get(arg)
            if pkg:
                packages.append(pkg)
                if not queue:
                    queue = 'priority'
                continue
            # try arg as a resource id
            res = model.Resource.get(arg)
            if res:
                resources.append(res)
                if not queue:
                    queue = 'priority'
                continue
            else:
                log.error('Could not recognize as a group, package '
                               'or resource: %r', arg)
                sys.exit(1)
    else:
        # all packages
        pkgs = model.Session.query(model.Package)\
                    .filter_by(state='active')\
                    .order_by('name').all()
        packages.extend(pkgs)
        if not queue:
            queue = 'bulk'

    if packages:
        log.info('Datasets to QA: %d', len(packages))
    if resources:
        log.info('Resources to QA: %d', len(resources))
    if not (packages or resources):
        log.error('No datasets or resources to process')
        sys.exit(1)

    log.info('Queue: %s', queue)
    for package in packages:
        lib.create_qa_update_package_task(package, queue)
        log.info('Queuing dataset %s (%s resources)',
                      package.name, len(package.resources))

    for resource in resources:
        package = resource.resource_group.package
        log.info('Queuing resource %s/%s', package.name, resource.id)
        lib.create_qa_update_task(resource, queue)

    log.info('Completed queueing')


def sniff(args):
    from ckanext.qa.sniff_format import sniff_file_format

    if not args:
        print('Not enough arguments', args)
        sys.exit(1)
    for filepath in args:
        format_ = sniff_file_format(
            filepath, logging.getLogger('ckanext.qa.sniffer'))
        if format_:
            print('Detected as: %s - %s' % (format_['display_name'],
                                            filepath))
        else:
            print('ERROR: Could not recognise format of: %s' % filepath)

def view(package_ref=None):
    from ckan import model

    q = model.Session.query(model.TaskStatus).filter_by(task_type='qa')
    print('QA records - %i TaskStatus rows' % q.count())
    print('      across %i Resources' % q.distinct('entity_id').count())

    if package_ref:
        pkg = model.Package.get(package_ref)
        print('Package %s %s' % (pkg.name, pkg.id))
        for res in pkg.resources:
            print('Resource %s' % res.id)
            for row in q.filter_by(entity_id=res.id):
                print('* %s = %r error=%r' % (row.key, row.value,
                                              row.error))


def clean():
    from ckan import model

    print('Before:')
    view()

    q = model.Session.query(model.TaskStatus).filter_by(task_type='qa')
    q.delete()
    model.Session.commit()

    print('After:')
    view()


def migrate1():
    from ckan import model
    from ckan.lib.helpers import json
    q_status = model.Session.query(model.TaskStatus) \
        .filter_by(task_type='qa') \
        .filter_by(key='status')
    print('* %s with "status" will be deleted e.g. %s' % (q_status.count(),
                                                          q_status.first()))
    q_failures = model.Session.query(model.TaskStatus) \
        .filter_by(task_type='qa') \
        .filter_by(key='openness_score_failure_count')
    print('* %s with openness_score_failure_count to be deleted e.g.\n%s'\
        % (q_failures.count(), q_failures.first()))
    q_score = model.Session.query(model.TaskStatus) \
        .filter_by(task_type='qa') \
        .filter_by(key='openness_score')
    print('* %s with openness_score to migrate e.g.\n%s' % \
        (q_score.count(), q_score.first()))
    q_reason = model.Session.query(model.TaskStatus) \
        .filter_by(task_type='qa') \
        .filter_by(key='openness_score_reason')
    print('* %s with openness_score_reason to migrate e.g.\n%s' % \
        (q_reason.count(), q_reason.first()))
    raw_input('Press Enter to continue')

    q_status.delete()
    model.Session.commit()
    print('..."status" deleted')

    q_failures.delete()
    model.Session.commit()
    print('..."openness_score_failure_count" deleted')

    for task_status in q_score:
        reason_task_status = q_reason \
            .filter_by(entity_id=task_status.entity_id) \
            .first()
        if reason_task_status:
            reason = reason_task_status.value
            reason_task_status.delete()
        else:
            reason = None

        task_status.key = 'status'
        task_status.error = json.dumps({
            'reason': reason,
            'format': None,
            'is_broken': None,
            })
        model.Session.commit()
    print('..."openness_score" and "openness_score_reason" migrated')

    count = q_reason.count()
    q_reason.delete()
    model.Session.commit()
    print('... %i remaining "openness_score_reason" deleted' % count)

    model.Session.flush()
    model.Session.remove()
    print('Migration succeeded')


def check_link_route():

    """
        Checks the given urls by making a HEAD request for them.

        Returns a list of dicts (one for each url) containing information
        gathered about that url.  Serialized as json.

        Each dict in the returned list has the form: ::

        {
          'url_errors': [ list of error messages that indicate the url is bad ],
          'inner_format': "A guess at the inner-most format",
          'format': "A guess at nested formats",
          'mimetype': "The mimetype returned in the HEAD request (Content-Type header)",
          'size': "The content-length returned in the HEAD request",
          'last_modified': "The 'last-modified' returned in the HEAD request",
        }

        where:

        url_errors : list of Strings corresponding to the following possible errors:
            * Invalid URL scheme (must be "http", "https" or "ftp")
            * Invalid URL (if the string doesn't seem to be a valid URL)
            * HTTP Error
            * Timeout

        format/inner_format: A best guess at the format of the file
            * a_file.csv has format "csv" and inner-format "csv"
            * a_file.csv.gz.torrent has inner-format "csv" and format "torrent:gz:csv"
            * This inspects the url and pulls out the file-extension(s) from it.
            * If that fails, then the "Content-Type" header is inspected, and passed to
              `mimetypes.guess_extension()` to make a reasonable guess at the file extension
            * May be None if unknown/un-guessable.

        mimetype: The Content-Type as returned in the HTTP headers
            * Stripped of character encoding parameters if they exist
            * Is the 'outer' mimetype as described in [2]

        size / last_modified: Just taken from the response headers.

        TODO:
        =====

         [ ] Maybe it's better to parse the url that the HEAD request gets
             redirected to.  eg [1] gets redirected to a listings page, [2] ?

             [1] http://www.ons.gov.uk/ons/dcp19975_226817.xml
             [2] http://www.ons.gov.uk/ons/rel/regional-trends/region-and-country-profiles/social-indicators/index.html
        """
    try:
        urls = tk.request.GET.getall("url")
    except AttributeError:
        urls = tk.request.args.getlist("url")
    result = [_check_link(url) for url in urls]
    return json.dumps(result)


def _check_link(url):
    """
        Synchronously check the given link, and return dict representing results.
        Does not handle 30x redirects.
        """

    # If a user enters "www.example.com" then we assume they meant "http://www.example.com"
    scheme, path = urllib.splittype(url)
    if not scheme:
        url = "http://" + path

    context = {}
    data = {"url_timeout": 10, "url": url}
    result = {
        "errors": [],
        "url_errors": [],
        "format": "",
        "mimetype": "",
        "size": "",
        "last_modified": "",
    }

    try:
        headers = json.loads(
            link_checker(json.dumps(context), json.dumps(data))
        )
        result["format"] = _extract_file_format(url, headers)
        result["mimetype"] = _extract_mimetype(headers)
        result["size"] = headers.get("content-length", "")
        result["last_modified"] = _parse_and_format_date(
            headers.get("last-modified", "")
        )
    except LinkCheckerError as e:
        result["url_errors"].append(str(e))
    return result


def _extract_file_format(url, headers):
    """
        Makes a best guess at the file format.

        /path/to/a_file.csv has format "CSV"
        /path/to/a_file.csv.zip has format "CSV / Zip"

        First this function tries to extract the file-extensions from the url,
        and deduce the format from there.  If no file-extension is found, then
        the mimetype from the headers is passed to `mimetypes.guess_extension()`.
        """
    formats = []
    parsed_url = urlparse(url)
    path = parsed_url.path
    base, extension = posixpath.splitext(path)
    while extension:
        formats.append(
            extension[1:].upper()
        )  # strip leading '.' from extension
        base, extension = posixpath.splitext(base)
    if formats:
        extension = ".".join(formats[::-1]).lower()
        format_tuple = ckan_helpers.resource_formats().get(extension)
        if format_tuple:
            return format_tuple[1]
        return " / ".join(formats[::-1])

    # No file extension found, attempt to extract format using the mimetype
    stripped_mimetype = _extract_mimetype(headers)  # stripped of charset
    format_tuple = ckan_helpers.resource_formats().get(stripped_mimetype)
    if format_tuple:
        return format_tuple[1]

    extension = mimetypes.guess_extension(stripped_mimetype)
    if extension:
        return extension[1:].upper()


def _extract_mimetype(headers):
    """
        The Content-Type in headers, stripped of character encoding parameters.
        """
    return headers.get("content-type", "").split(";")[0].strip()


def _parse_and_format_date(date_string):
    """
        Parse date string in form specified in RFC 2822, and reformat to iso format.

        Returns the empty string if the date_string cannot be parsed
        """
    dt = parse_rfc_2822_date(date_string)

    # Remove timezone information, adjusting as necessary.
    if dt and dt.tzinfo:
        dt = (dt - dt.utcoffset()).replace(tzinfo=None)
    return dt.isoformat() if dt else ""
