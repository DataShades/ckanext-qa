import click
import ckanext.qa.utils as utils


def get_commands():
    return [qa]


@click.group()
def qa():
    pass


# @click.option('-q', '--queue', required=False, nargs='*')


@qa.command()
@click.argument("args", nargs=-1)
@click.option("-q", "--queue", required=False)
def update(args, queue):
    utils.update(args, queue)


@qa.command()
@click.argument("args", nargs=-1)
def sniff(args):
    utils.sniff(args)


@qa.command()
def clean():
    utils.clean()


@qa.command()
def migrate1():
    utils.migrate1()


@qa.command()
def init():
    utils.init_db()


@qa.command()
@click.argument("package_ref", required=False)
def view(package_ref):
    utils.view(package_ref)
