# -*- coding: utf-8 -*-
"""
    flask_principal
    ~~~~~~~~~~~~~~~

    Identity management for Flask.

    :copyright: (c) 2012 by Ali Afshar.
    :license: MIT, see LICENSE for more details.

"""

from __future__ import with_statement

__version__ = '0.4.1'

import sys

from functools import partial, wraps
from collections import deque

from collections import namedtuple

from flask import g, session, current_app, abort, request
from flask.signals import Namespace

PY3 = sys.version_info[0] == 3

signals = Namespace()


identity_changed = signals.signal('identity-changed', doc="""
Signal sent when the identity for a request has been changed.

Actual name: ``identity-changed``

Authentication providers should send this signal when authentication has been
successfully performed. Flask-Principal connects to this signal and
causes the identity to be saved in the session.

For example::

    from flask_principal import Identity, identity_changed

    def login_view(req):
        username = req.form.get('username')
        # check the credentials
        identity_changed.send(app, identity=Identity(username))
""")


identity_loaded = signals.signal('identity-loaded', doc="""
Signal sent when the identity has been initialised for a request.

Actual name: ``identity-loaded``

Identity information providers should connect to this signal to perform two
major activities:

    1. Populate the identity object with the
       necessary authorization provisions.
    2. Load any additional user information.

For example::

    from flask_principal import identity_loaded, RoleNeed, UserNeed

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


UserNeed = partial(Need, 'id')
UserNeed.__doc__ = """A need with the method preset to `"id"`."""


RoleNeed = partial(Need, 'role')
RoleNeed.__doc__ = """A need with the method preset to `"role"`."""


TypeNeed = partial(Need, 'type')
TypeNeed.__doc__ = """A need with the method preset to `"type"`."""


ActionNeed = partial(Need, 'action')
ActionNeed.__doc__ = """A need with the method preset to `"action"`."""


ItemNeed = namedtuple('ItemNeed', ['method', 'value', 'type'])
"""A required item need

An item need is just a named tuple, and practically any tuple will do. In
addition to other Needs, there is a type, for example this could be specified
as::

    ItemNeed('update', 27, 'posts')
    ('update', 27, 'posts') # or like this

And that might describe the permission to update a particular blog post. In
reality, the developer is free to choose whatever convention the permissions
are.
"""


class PermissionDenied(RuntimeError):
    """Permission denied to the resource."""


class Identity(object):
    """Represent the user's identity.

    The identity is used to represent the user's identity in the system. This
    object is created on login, or on the start of the request as loaded from
    the user's session.

    Once loaded it is sent using the `identity-loaded` signal, and should be
    populated with additional required information.

    Needs that are provided by this identity should be added to the `provides`
    set after loading.

    Args:
        id: The user id.
        auth_type: The authentication type used to confirm the user's identity.

    """
    def __init__(self, id, auth_type=None):
        self.id = id
        self.auth_type = auth_type
        self.provides = set()

    def can(self, permission):
        """Whether the identity has access to the permission.

        Args:
            permission (Permission): The permission to test provision for.

        Returns:
            bool

        """

        return permission.allows(self)

    def __repr__(self):
        return '<{0} id="{1}" auth_type="{2}" provides={3}>'.format(
            self.__class__.__name__, self.id, self.auth_type, self.provides
        )


class AnonymousIdentity(Identity):
    """An anonymous identity."""

    def __init__(self):
        Identity.__init__(self, None)


class IdentityContext(object):
    """The context of an identity for a permission.

    .. note:: The principal is usually created by the
              flask_principal.Permission.require method
              call for normal use-cases.

    The principal behaves as either a context manager or a decorator. The
    permission is checked for provision in the identity, and if available the
    flow is continued (context manager) or the function is executed (decorator)

    """

    def __init__(self, permission, http_exception=None):
        """The permission of this principal.

        Args:
            permission (BasePermission): The permission being attached.
            http_exception: Exception code to throw.

        """
        self.permission = permission
        self.http_exception = http_exception

    @property
    def identity(self):
        """The identity of this principal."""
        return g.identity

    def can(self):
        """Whether the identity has access to the permission."""
        return self.identity.can(self.permission)

    def __call__(self, f):
        @wraps(f)
        def _decorated(*args, **kw):
            with self:
                rv = f(*args, **kw)
            return rv
        return _decorated

    def __enter__(self):
        # check the permission here
        if not self.can():
            if self.http_exception:
                abort(self.http_exception, self.permission)
            raise PermissionDenied(self.permission)

    def __exit__(self, *args):
        return False


class BasePermission(object):
    """The Base Permission."""

    http_exception = None

    def _bool(self):
        return bool(self.can())

    def __nonzero__(self):
        """Equivalent to ``self.can()``."""
        return self._bool()

    def __bool__(self):
        """Equivalent to ``self.can()``."""
        return self._bool()

    def __or__(self, other):
        """See ``OrPermission``."""
        return self.or_(other)

    def or_(self, other):
        """Define or operator.

        Args:
            other: Take another permission object.

        """
        return OrPermission(self, other)

    def __and__(self, other):
        """See ``AndPermission``."""
        return self.and_(other)

    def and_(self, other):
        """Define and operator.

        Args:
            other: Take another permission object.

        """
        return AndPermission(self, other)

    def __invert__(self):
        """See ``NotPermission``."""
        return self.invert()

    def invert(self):
        """See ``invert``."""
        return NotPermission(self)

    def require(self, http_exception=403):
        """Create a principal for this permission.

        The principal may be used as a context manager, or a decroator.

        If ``http_exception`` is passed then ``abort()`` will be called
        with the HTTP exception code. Otherwise a ``PermissionDenied``
        exception will be raised if the identity does not meet the
        requirements.

        Args:
            http_exception: the HTTP exception code (403, 401 etc)

        Returns:
            IdentityContext

        """

        if http_exception is None:
            http_exception = self.http_exception

        return IdentityContext(self, http_exception)

    def test(self, http_exception=None):
        """
        Checks if permission available and raises relevant exception
        if not. This is useful if you just want to check permission
        without wrapping everything in a require() block.

        This is equivalent to::

            with permission.require():
                pass
        """

        with self.require(http_exception):
            pass

    def allows(self, identity):
        """Whether the identity can access this permission.

        Args:
            identity: The identity

        """

        raise NotImplementedError

    def can(self):
        """Whether the required context for this permission has access.

        This creates an identity context and tests whether it can access this
        permission

        """
        return self.require().can()


class _NaryOperatorPermission(BasePermission):

    def __init__(self, *permissions):
        self.permissions = set(permissions)


# These classes would be unnecessary if we have predicate calculus
# primatives of some kind.

class OrPermission(_NaryOperatorPermission):
    """Result of bitwise ``or`` of BasePermission."""

    def allows(self, identity):
        """
        Checks for any of the nested permission instances that allow the
        identity and return True, else return False.

        Args:
            identity: The identity.

        """

        for p in self.permissions:
            if p.allows(identity):
                return True
        return False


class AndPermission(_NaryOperatorPermission):
    """Result of bitwise ``and`` of BasePermission"""

    def allows(self, identity):
        """
        Checks for any of the nested permission instances that disallow
        the identity and return False, else return True.

        Args:
            identity: The identity.

        Returns:
            bool

        """
        for p in self.permissions:
            if not p.allows(identity):
                return False

        return True


class NotPermission(BasePermission):
    """
    Result of bitwise ``not`` of BasePermission

    Really could be implemented by returning a transformed result of the
    source class of itself, but for the sake of clear presentation I am
    not doing that.

    """

    def __init__(self, permission):
        self.permission = permission

    def invert(self):
        return self.permission

    def allows(self, identity):
        """
        Checks for any of the nested permission instances that disallow
        the identity and return False, else return True.

        Args:
            identity: The identity.

        Returns:
            bool

        """
        return not self.permission.allows(identity)


class Permission(BasePermission):
    """Represents needs, any of which must be present to access a resource

    Args:
        needs: The needs for this permission

    """

    def __init__(self, *needs):
        """A set of needs.

        Any of which must be present in an identity to have access.

        """

        self.needs = set(needs)
        self.excludes = set()

    def __or__(self, other):
        """Does the same thing as ``self.union(other)``."""
        if isinstance(other, Permission):
            return self.union(other)
        return super(Permission, self).__or__(other)

    def __sub__(self, other):
        """Does the same thing as ``self.difference(other)``."""
        return self.difference(other)

    def __contains__(self, other):
        """Does the same thing as ``other.issubset(self)``."""
        return other.issubset(self)

    def __repr__(self):
        return '<{0} needs={1} excludes={2}>'.format(
            self.__class__.__name__, self.needs, self.excludes
        )

    def reverse(self):
        """Returns reverse of current state.

        (needs->excludes, excludes->needs)

        Returns:
            Permission: The permission inverted

        """

        p = Permission()
        p.needs.update(self.excludes)
        p.excludes.update(self.needs)
        return p

    def union(self, other):
        """Create a new permission with the requirements of the union of this
        and other.

        Args:
            other: The other permission

        Returns:
            Permission: The permission union.

        """
        p = Permission(*self.needs.union(other.needs))
        p.excludes.update(self.excludes.union(other.excludes))
        return p

    def difference(self, other):
        """Create a new permission consisting of requirements in this
        permission and not in the other.

        Args:
            other: The other permission

        Returns:
            Permission: The permission difference.

        """
        p = Permission(*self.needs.difference(other.needs))
        p.excludes.update(self.excludes.difference(other.excludes))
        return p

    def issubset(self, other):
        """Whether this permission needs are a subset of another

        Args:
            other: The other permission

        Returns:
            bool

        """
        return (
            self.needs.issubset(other.needs) and
            self.excludes.issubset(other.excludes)
        )

    def allows(self, identity):
        """Whether the identity can access this permission.
        Args:
            identity: The identity.

        Returns:
            bool

        """
        if self.needs and not self.needs.intersection(identity.provides):
            return False

        if self.excludes and self.excludes.intersection(identity.provides):
            return False

        return True


class Denial(Permission):
    """Shortcut class for passing excluded needs."""

    def __init__(self, *excludes):
        self.excludes = set(excludes)
        self.needs = set()


def session_identity_loader():
    """Load session identity."""
    if 'identity.id' in session and 'identity.auth_type' in session:
        identity = Identity(session['identity.id'],
                            session['identity.auth_type'])
        return identity


def session_identity_saver(identity):
    """Save session identity."""
    session['identity.id'] = identity.id
    session['identity.auth_type'] = identity.auth_type
    session.modified = True


class Principal(object):
    """Principal extension.

    Args:
        app: The flask application to extend
        use_sessions (bool): Whether to use sessions to extract and store
                             identification.
        skip_static (bool): Whether to ignore static endpoints.

    """
    def __init__(self, app=None, use_sessions=True, skip_static=False):
        self.identity_loaders = deque()
        self.identity_savers = deque()
        # XXX This will probably vanish for a better API
        self.use_sessions = use_sessions
        self.skip_static = skip_static

        if app is not None:
            self.init_app(app)

    def _init_app(self, app):
        from warnings import warn
        warn(
            DeprecationWarning(
                '_init_app is deprecated, use the new init_app '
                'method instead.'
            ), stacklevel=1
        )
        self.init_app(app)

    def init_app(self, app):
        """Initialize a new principal."""
        if hasattr(app, 'static_url_path'):
            self._static_path = app.static_url_path
        else:
            self._static_path = app.static_path

        app.before_request(self._on_before_request)
        identity_changed.connect(self._on_identity_changed, app)

        if self.use_sessions:
            self.identity_loader(session_identity_loader)
            self.identity_saver(session_identity_saver)

    def set_identity(self, identity):
        """Set the current identity.

        Args:
            identity: The identity to set

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

            principals = Principal(app)

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

            principals = Principal(app)

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
        if self._is_static_route():
            return

        self.set_identity(identity)

    def _on_before_request(self):
        if self._is_static_route():
            return

        g.identity = AnonymousIdentity()
        for loader in self.identity_loaders:
            identity = loader()
            if identity is not None:
                self.set_identity(identity)
                return

    def _is_static_route(self):
        return (
            self.skip_static and
            (self._static_path and request.path.startswith(self._static_path))
        )
