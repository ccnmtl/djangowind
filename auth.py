from django.conf import settings
from django.contrib.auth.models import User, Group, check_password
import urllib
import simplejson
from restclient import GET
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
                user.email = username + "@columbia.edu"
                cdap_base = "http://cdap.ccnmtl.columbia.edu/"
                if hasattr(settings,'CDAP_BASE'):
                    cdap_base = settings.CDAP_BASE
                r = simplejson.loads(GET(cdap_base + "?uni=%s" % username))
                if r['found']:
                    user.last_name = r['lastname'] or r['sn']
                    user.first_name = r['firstname'] or r['givenName']
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

    def load_mapper(self,path):
        i = path.rfind('.')
        module, attr = path[:i], path[i+1:]
        try:
            mod = __import__(module, {}, {}, [attr])
        except ImportError, e:
            raise ImproperlyConfigured, 'Error importing wind affil handler %s: "%s"' % (module, e)
        except ValueError, e:
            raise ImproperlyConfigured, 'Error importing wind affil handler. Is WIND_AFFIL_HANDLERS a correctly defined list or tuple?'
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
            mappers.append(self.load_mapper(mapper_path))
        return mappers

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


