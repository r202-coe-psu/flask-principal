# -*- coding: utf-8 -*-
"""
    flaskext.principal
    ~~~~~~~~~~~~~~~~~~

    Identity management for Flask.

    :copyright: (c) 2010 by Ali Afshar.
    :license: MIT, see LICENSE for more details.

"""

import sys
from functools import partial, wraps
from collections import namedtuple, deque


from flask import g, session, current_app
from flask.signals import Namespace


signals = Namespace()
"""Namespace for principal's signals.
"""


identity_changed = signals.signal('identity-changed', doc=
"""Signal sent when the identity for a request has been changed.

Actual name: ``identity-changed``

Authentication providers should send this signal when authentication has been
successfully performed. Flask-Principal connects to this signal and causes the
identity to be saved in the session.

For example::

    from flaskext.principal import Identity, identity_changed

    def login_view(req):
        username = req.form.get('username')
        # check the credentials
        identity_changed.send(app, identity=Identity(username))
""")


identity_loaded = signals.signal('identity-loaded', doc=
"""Signal sent when the identity has been initialised for a request.

Actual name: ``identity-loaded``

Identity information providers should connect to this signal to perform two
major activities:

    1. Populate the identity object with the necessary authorization provisions.
    2. Load any additional user information.

For example::

    from flaskext.principal import indentity_loaded, RoleNeed, UserNeed

    @identity_loaded.connect
    def on_identity_loaded(sender, identity):
        # Get the user information from the db
        user = db.get(identity.name)
        # Update the roles that a user can provide
        for role in user.roles:
            identity.provides.add(RoleNeed(role.name))
        # Save the user somewhere so we only look it up once
        identity.user = user
""")


Need = namedtuple('Need', ['method', 'value'])
"""A required need

This is just a named tuple, and practically any tuple will do.

The ``method`` attribute can be used to look up element 0, and the ``value``
attribute can be used to look up element 1.
"""


UserNeed = partial(Need, 'name')
"""A need with the method preset to `"name"`.
"""


RoleNeed = partial(Need, 'role')
"""A need with the method preset to `"role"`.
"""


class PermissionDenied(RuntimeError):
    """Permission denied to the resource
    """


class Identity(object):
    """Represent the user's identity.

    :param name: The username
    :param auth_type: The authentication type used to confirm the user's
                      identity.

    The identity is used to represent the user's identity in the system. This
    object is created on login, or on the start of the request as loaded from
    the user's session.

    Once loaded it is sent using the `identity-loaded` signal, and should be
    populated with additional required information.

    Needs that are provided by this identity should be added to the `provides`
    set after loading.
    """
    def __init__(self, name, auth_type=''):
        self.name = name
        self.auth_type = auth_type

        self.provides = set()
        """A set of needs provided by this user

        Provisions can be added using the `add` method, for example::

            identity = Identity('ali')
            identity.provides.add(('role', 'admin'))
        """

    def can(self, permission):
        """Whether the identity has access to the permission.

        :param permission: The permission to test provision for.
        """
        if not permission.needs:
            return True
        else:
            return permission.needs.intersection(self.provides)


class AnonymousIdentity(Identity):
    """An anonymous identity

    :attr name: `"anon"`
    """

    def __init__(self):
        Identity.__init__(self, 'anon')


class Principal(object):
    """The context of an identity for a permission.

    .. note:: The principal is usually created by the flaskext.Permission.require method
              call for normal use-cases.

    The principal behaves as either a context manager or a decorator. The
    permission is checked for provision in the identity, and if available the
    flow is continued (context manager) or the function is executed (decorator).
    """

    def __init__(self, permission):
        self.permission = permission
        """The permission of this principal
        """

    @property
    def identity(self):
        """The identity of this principal
        """
        return g.identity

    def can(self):
        """Whether the identity has access to the permission
        """
        return self.identity.can(self.permission)

    def __call__(self, f):
        @wraps(f)
        def _decorated(*args, **kw):
            self.__enter__()
            exc = (None, None, None)
            try:
                result = f(*args, **kw)
            except Exception:
                exc = sys.exc_info()
            self.__exit__(*exc)
            return result
        return _decorated

    def __enter__(self):
        # check the permission here
        if not self.can():
            raise PermissionDenied(self.permission)

    def __exit__(self, *exc):
        if exc != (None, None, None):
            cls, val, tb = exc
            raise cls, val, tb
        return False


class Permission(object):
    """Represents needs, any of which must be present to access a resource

    :param needs: The needs for this permission
    """
    def __init__(self, *needs):
        self.needs = set(needs)
        """A set of needs, any of which must be present in an identity to have
        access.
        """

    def require(self):
        """Create a principal for this permission.

        The principal may be used as a context manager, or a decroator.
        """
        return Principal(self)

    def union(self, other):
        """Create a new permission with the requirements of the union of this
        and other.

        :param other: The other permission
        """
        return Permission(*self.needs.union(other.needs))

    def issubset(self, other):
        """Whether this permission needs are a subset of another

        :param other: The other permission
        """
        return self.needs.issubset(other.needs)


def session_identity_loader():
    if 'identity.name' in session and 'identity.auth_type' in session:
        identity = Identity(session['identity.name'],
                            session['identity.auth_type'])
        return identity


def session_identity_saver(identity):
    session['identity.name'] = identity.name
    session['identity.auth_type'] = identity.auth_type
    session.modified = True


class Principals(object):
    """Principals extension

    :param app: The flask application to extend
    :param use_sessions: Whether to use sessions to extract and store
                         identification.
    """
    def __init__(self, app, use_sessions=True):
        self.app = app
        self.identity_loaders = deque()
        self.identity_savers = deque()
        app.before_request(self._on_before_request)
        identity_changed.connect(self._on_identity_changed, app)

        if use_sessions:
            self.identity_loader(session_identity_loader)
            self.identity_saver(session_identity_saver)

    def set_identity(self, identity):
        """Set the current identity.

        :param identity: The identity to set
        """
        self._set_thread_identity(identity)
        for saver in self.identity_savers:
            saver(identity)

    def identity_loader(self, f):
        """Decorator to define a function as an identity loader.

        An identity loader function is called before request to find any
        provided identities. The first found identity is used to load from.

        For example::

        app = Flask(__name__)

        principals = Principals(app)

        @principals.identity_loader
        def load_identity_from_weird_usecase():
            return Identity('ali')
        """
        self.identity_loaders.appendleft(f)
        return f

    def identity_saver(self, f):
        """Decorator to define a function as an identity saver.

        An identity loader saver is called when the identity is set to persist
        it for the next request.

        For example::

        app = Flask(__name__)

        principals = Principals(app)

        @principals.identity_saver
        def save_identity_to_weird_usecase(identity):
            my_special_cookie['identity'] = identity
        """
        self.identity_savers.appendleft(f)
        return f

    def _set_thread_identity(self, identity):
        g.identity = identity
        identity_loaded.send(current_app._get_current_object(),
                             identity=identity)

    def _on_identity_changed(self, app, identity):
        self.set_identity(identity)

    def _on_before_request(self):
        g.identity = AnonymousIdentity()
        for loader in self.identity_loaders:
            identity = loader()
            if identity is not None:
                self.set_identity(identity)
                return

