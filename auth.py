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
            print username # WIND error message
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
        from django.conf import settings
        mappers = []
        if not hasattr(settings,'WIND_AFFIL_HANDLERS'):
            return []
        for mapper_path in settings.WIND_AFFIL_HANDLERS:
            mappers.append(self.load_handler(mapper_path))
        return mappers

    def get_profile_handlers(self):
        from django.conf import settings
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

    # QUESTION: do we want to remove their username group?
    # I can see it getting noisy since, as is, a group is
    # created for every user.

    def map(self,user,affils):
        # we also make a "pseudo" affil group ALL_CU
        # that contains *anyone* who's logged in through WIND
        affils.append("ALL_CU")
        
        for affil in affils:
            try:
                group = Group.objects.get(name=affil)
            except Group.DoesNotExist:
                group = Group(name=affil)
                group.save()
            user.groups.add(group)
        user.save()
            

class TLCXMLStaffMapper:
    """ if the user is in tlcxml, it makes sure that the user
        is set as 'staff' """

    def map(self,user,affils):
        for affil in affils:
            if affil == 'tlcxml.cunix.local:columbia.edu':
                user.is_staff = True
                user.save()
                return


class TLCXMLSuperuserMapper:
    """ if the user is in tlcxml, it makes sure that the user
        is set as 'superuser' """

    def map(self,user,affils):
        for affil in affils:
            if affil == 'tlcxml.cunix.local:columbia.edu':
                user.is_superuser = True
                user.save()
                return


