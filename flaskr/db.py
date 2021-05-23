# -*- coding: utf-8 -*-

import sqlite3
import os
import flask
from flask import g, current_app
from flask.cli import with_appcontext
import click


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(
            current_app.config["DATABASE"],
            detect_types=sqlite3.PARSE_COLNAMES,
        )
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    schema_path = os.path.join(current_app.root_path, "schema.sql")
    with current_app.open_resource(schema_path) as f:
        db.executescript(f.read().decode("utf8"))


@click.command("init-db")
@with_appcontext
def init_db_command():
    init_db()
    click.echo("Initialized the database.")


def init_app(app: flask.Flask):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
