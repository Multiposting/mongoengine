from mongoengine import *

from django.contrib.auth.hashers import (
    check_password,
    make_password,
    is_password_usable,
)
from django.contrib.auth.models import (
    SiteProfileNotAvailable,
    _user_get_all_permissions,
    _user_has_perm,
    _user_has_module_perms,
)
from django.utils.translation import ugettext_lazy as _
from django.utils.encoding import python_2_unicode_compatible
from django.utils import timezone


@python_2_unicode_compatible
class AbstractBaseUser(Document):
    """Reimplementation of Django's AbstractBaseUser in Mongoengine."""

    meta = {
        'abstract': True,
    }

    password = StringField(max_length=128, verbose_name=_('password'))
    last_login = DateTimeField(default=timezone.now, verbose_name=_('last login'))

    is_active = True

    REQUIRED_FIELDS = []

    def get_username(self):
        "Return the identifying username for this User"
        return getattr(self, self.USERNAME_FIELD)

    def __str__(self):
        return self.get_username()

    def natural_key(self):
        return (self.get_username(),)

    def is_anonymous(self):
        """
        Always returns False. This is a way of comparing User objects to
        anonymous users.
        """
        return False

    def is_authenticated(self):
        """
        Always return True. This is a way to tell if the user has been
        authenticated in templates.
        """
        return True

    def set_password(self, raw_password):
        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        """
        Returns a boolean of whether the raw_password was correct. Handles
        hashing formats behind the scenes.
        """
        def setter(raw_password):
            self.set_password(raw_password)
            self.save(update_fields=["password"])
        return check_password(raw_password, self.password, setter)

    def set_unusable_password(self):
        # Sets a value that will never be a valid hash
        self.password = make_password(None)

    def has_usable_password(self):
        return is_password_usable(self.password)

    def get_full_name(self):
        raise NotImplementedError()

    def get_short_name(self):
        raise NotImplementedError()


class PermissionsMixin(Document):
    """Reimplementation of Django's PermissionsMixin in MongoEngine.

    Groups and individual Permissions are not supported, only the superuser
    status is implemented.

    """

    meta = {
        'abstract': True,
    }

    is_superuser = BooleanField(default=False, verbose_name=_('superuser status'),
        help_text=_('Designates that this user has all permissions without '
                    'explicitly assigning them.'))
    #groups = models.ManyToManyField(Group, verbose_name=_('groups'),
    #    blank=True, help_text=_('The groups this user belongs to. A user will '
    #                            'get all permissions granted to each of '
    #                            'his/her group.'))
    #user_permissions = models.ManyToManyField(Permission,
    #    verbose_name=_('user permissions'), blank=True,
    #    help_text='Specific permissions for this user.')

    def get_group_permissions(self, obj=None):
        """
        Returns a list of permission strings that this user has through his/her
        groups. This method queries all available auth backends. If an object
        is passed in, only permissions matching this object are returned.
        """
        permissions = set()
        for backend in auth.get_backends():
            if hasattr(backend, "get_group_permissions"):
                if obj is not None:
                    permissions.update(backend.get_group_permissions(self,
                                                                     obj))
                else:
                    permissions.update(backend.get_group_permissions(self))
        return permissions

    def get_all_permissions(self, obj=None):
        return _user_get_all_permissions(self, obj)

    def has_perm(self, perm, obj=None):
        """
        Returns True if the user has the specified permission. This method
        queries all available auth backends, but returns immediately if any
        backend returns True. Thus, a user who has permission from a single
        auth backend is assumed to have permission in general. If an object is
        provided, permissions for this specific object are checked.
        """

        # Active superusers have all permissions.
        if self.is_active and self.is_superuser:
            return True

        # Otherwise we need to check the backends.
        return _user_has_perm(self, perm, obj)

    def has_perms(self, perm_list, obj=None):
        """
        Returns True if the user has each of the specified permissions. If
        object is passed, it checks if the user has all required perms for this
        object.
        """
        for perm in perm_list:
            if not self.has_perm(perm, obj):
                return False
        return True

    def has_module_perms(self, app_label):
        """
        Returns True if the user has any permissions in the given app label.
        Uses pretty much the same logic as has_perm, above.
        """
        # Active superusers have all permissions.
        if self.is_active and self.is_superuser:
            return True

        return _user_has_module_perms(self, app_label)


class AbstractUser(AbstractBaseUser, PermissionsMixin):
    """Reimplementation of Django's AbstractUser in MongoEngine.

    Username, password and email are required. Other fields are optional.

    """

    meta = {
        'abstract': True,
        'indexes': [
            {'fields': ['username'], 'unique': True, 'sparse': True}
        ],
    }

    username = StringField(
        max_length=30, required=True, verbose_name=_('username'),
        help_text=_('Required. 30 characters or fewer. Letters, numbers and '
                    '@/./+/-/_ characters'))
    first_name = StringField(max_length=30, verbose_name=_('first name'))
    last_name = StringField(max_length=30, verbose_name=_('last name'))
    email = EmailField(verbose_name=_('e-mail address'))

    is_staff = BooleanField(default=False, verbose_name=_('staff status'),
        help_text=_('Designates whether the user can log into this admin '
                    'site.'))
    is_active = BooleanField(default=True, verbose_name=_('active'),
        help_text=_('Designates whether this user should be treated as '
                    'active. Unselect this instead of deleting accounts.'))

    date_joined = DateTimeField(default=timezone.now, verbose_name=_('date joined'))

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    def get_absolute_url(self):
        return "/users/%s/" % urlquote(self.username)

    def get_full_name(self):
        """
        Returns the first_name plus the last_name, with a space in between.
        """
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        "Returns the short name for the user."
        return self.first_name

    def email_user(self, subject, message, from_email=None):
        """
        Sends an email to this User.
        """
        send_mail(subject, message, from_email, [self.email])

    def get_profile(self):
        """Site Profile relations are not supported in MongoEngine."""
        raise SiteProfileNotAvailable


class User(AbstractUser):
    """Default user document used by MongoEngine.

    Inherit from AbstractBaseUser or AbstractUser to define your own user
    implementation, and configure it in MONGOENGINE_USER_DOCUMENT.

    """

