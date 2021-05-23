# -*- coding: utf-8 -*-

import functools

import flask
from flaskr.db import get_db
from werkzeug.security import check_password_hash, generate_password_hash

bp = flask.Blueprint("auth", __name__, url_prefix="/auth")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if flask.request.method == "POST":
        username = flask.request.form["username"]
        password = flask.request.form["password"]
        db = get_db()
        err = None

        if not username:
            err = "Username is required."
        elif not password:
            err = "Password is required."
        elif (
            db.execute(
                "SELECT id FROM user WHERE username = ?",
                (username,),
            ).fetchone()
            is not None
        ):
            err = "User {} is already registered.".format(username)

        if err is None:
            db.execute(
                "INSERT INTO user (username, password) VALUES (?, ?)",
                (
                    username,
                    generate_password_hash(password),
                ),
            )
            db.commit()
            return flask.redirect(flask.url_for("auth.login"))
        flask.flash(err)
    return flask.render_template("auth/register.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if flask.request.method == "POST":
        username = flask.request.form["username"]
        password = flask.request.form["password"]
        db = get_db()
        err = None

        if not username:
            err = "Username is required."
        elif not password:
            err = "Password is required."

        if err is None:
            user = db.execute(
                "SELECT * FROM user WHERE username = ?",
                (username,),
            ).fetchone()
            if user == None or not check_password_hash(user["password"], password):
                err = "Login failed."

        if err is None:
            flask.session.clear()
            flask.session["user_id"] = user["id"]
            return flask.redirect(flask.url_for("blog.index"))
        flask.flash(err)
    return flask.render_template("auth/login.html")


@bp.before_app_request
def load_logged_in_user():
    user_id = flask.session.get("user_id", default=None)
    if user_id is None:
        flask.g.user = None
    else:
        flask.g.user = (
            get_db().execute("SELECT * FROM user WHERE id = ?", (user_id,)).fetchone()
        )


@bp.route("/logout")
def logout():
    flask.session.clear()
    return flask.redirect(flask.url_for("blog.index"))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if flask.g.user is None:
            return flask.redirect(flask.url_for("auth.login"))
        return view(**kwargs)

    return wrapped_view
