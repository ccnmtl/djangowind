from django.conf import settings
from django.contrib.auth.models import User, Group, check_password
import urllib
from django.core.exceptions import ImproperlyConfigured

def validate_wind_ticket(ticketid):
    """
    checks a wind ticketid.
    if successful, it returns (True,username)
    otherwise it returns (False,error message)
    """

    if ticketid == "":
        return (False,'no ticketid','')
    wind_base = "https://wind.columbia.edu/"
    if hasattr(settings,'WIND_BASE'):
        wind_base = getattr(settings,'WIND_BASE')
    uri = wind_base + "validate?ticketid=%s" % ticketid
    response = urllib.urlopen(uri).read()
    lines = response.split("\n")
    if lines[0] == "yes":
        username = lines[1]
        groups = [line for line in lines[1:] if line != ""]
        return (True,username,groups)
    elif lines[0] == "no":
        return (False,"The ticket was already used or was invalid.",[])
    else:
        return (False,"WIND did not return a valid response.",[])

class WindAuthBackend:
    def authenticate(self, ticket=None):
        if ticket is None:
            return None
        (response,username,groups) = validate_wind_ticket(ticket)
        if response is True:
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                user = User(username=username, password='wind user')
                user.set_unusable_password()
                for handler in self.get_profile_handlers():
                    handler.process(user)
                user.save()

            for handler in self.get_mappers():
                handler.map(user,groups)
            return user
        else:
            # i don't know how to actually get this error message
            # to bubble back up to the user. must dig into
            # django auth deeper. 
            pass
        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def load_handler(self,path):
        i = path.rfind('.')
        module, attr = path[:i], path[i+1:]
        try:
            mod = __import__(module, {}, {}, [attr])
        except ImportError, e:
            raise ImproperlyConfigured, 'Error importing wind handler %s: "%s"' % (module, e)
        except ValueError, e:
            raise ImproperlyConfigured, 'Error importing wind handler. '
        try:
            cls = getattr(mod, attr)
        except AttributeError:
            raise ImproperlyConfigured, 'Module "%s" does not define a "%s" authentication backend' % (module, attr)
        return cls()

    def get_mappers(self):
        mappers = []
        if not hasattr(settings,'WIND_AFFIL_HANDLERS'):
            return []
        for mapper_path in settings.WIND_AFFIL_HANDLERS:
            mappers.append(self.load_handler(mapper_path))
        return mappers

    def get_profile_handlers(self):
        handlers = []
        if not hasattr(settings,'WIND_PROFILE_HANDLERS'):
            return []
        for handler_path in settings.WIND_PROFILE_HANDLERS:
            handlers.append(self.load_handler(handler_path))
        return handlers    

class CDAPProfileHandler:
    """ fills in email, last_name, first_name from CDAP """
    def process(self,user):
        from restclient import GET
        import httplib2
        import simplejson
        user.email = user.username + "@columbia.edu"
        cdap_base = "http://cdap.ccnmtl.columbia.edu/"
        if hasattr(settings,'CDAP_BASE'):
            cdap_base = settings.CDAP_BASE
        try:
            r = simplejson.loads(GET(cdap_base + "?uni=%s" % user.username))
            if r.get('found',False):
                user.last_name = r.get('lastname',r.get('sn',''))
                user.first_name = r.get('firstname',r.get('givenName',''))
        except httplib2.ServerNotFoundError:
            # cdap.ccnmtl.columbia.edu (or whatever the CDAP server is set to)
            # is probably not in /etc/hosts on this server
            pass
        user.save()

class AffilGroupMapper:
    """ makes sure that the user is in a Group for every wind affil,
        autovivifying Groups if necessary """

    def map(self,user,affils):
        # we also make a "pseudo" affil group ALL_CU
        # that contains *anyone* who's logged in through WIND
        affils.append("ALL_CU")

        # by default, WIND affils include a group named for
        # the uni for each user. This is not usually desirable
        # so we strip it out, but there's a setting that lets
        # you turn it back on. 
        remove_uni = True
        if hasattr(settings,'WIND_AFFIL_GROUP_INCLUDE_UNI_GROUP'):
            if settings.WIND_AFFIL_GROUP_INCLUDE_UNI_GROUP is True:
                remove_uni = False

        for affil in affils:
            if remove_uni and (affil == user.username):
                continue
            try:
                group = Group.objects.get(name=affil)
            except Group.DoesNotExist:
                group = Group(name=affil)
                group.save()
            user.groups.add(group)
        user.save()
            

class StaffMapper:
    """ if the user is in one of the specified wind affil groups,
        it makes sure that the user is set as 'staff' """

    def __init__(self):
        if not hasattr(settings,'WIND_STAFF_MAPPER_GROUPS'):
            self.groups = []
        self.groups = settings.WIND_STAFF_MAPPER_GROUPS

    def map(self,user,affils):
        for affil in affils:
            if affil in self.groups:
                user.is_staff = True
                user.save()
                return


class SuperuserMapper:
    """ if the user is in one of the specified wind affil groups,
        it makes sure that the user is set as 'superuser' """

    def __init__(self):
        if not hasattr(settings,'WIND_SUPERUSER_MAPPER_GROUPS'):
            self.groups = []
        self.groups = settings.WIND_SUPERUSER_MAPPER_GROUPS

    def map(self,user,affils):
        for affil in affils:
            if affil in self.groups:
                user.is_superuser = True
                user.is_staff = True
                user.save()
                return


