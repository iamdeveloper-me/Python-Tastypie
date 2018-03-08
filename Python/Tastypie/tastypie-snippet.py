import json
import urlparse
from copy import deepcopy

from django.conf import settings

from tastypie import fields
from tastypie.resources import Resource
from tastypie.exceptions import ImmediateHttpResponse
from tastypie.bundle import Bundle
from tastypie.authentication import Authentication
from tastypie import http
from tastypie.serializers import Serializer
from tastypie.utils import dict_strip_unicode_keys

from fccommon.models import NFLMatch
from fcgame.models import UserGame, GameUser
from fcgame.api import VerboseSerializer
from gamefunctions import MSupervisor
from fantasycoached import constants
from api import ScorerResource

import logging
logger = logging.getLogger("api")

class CustomAuthenticationBase(Authentication):
    def get_api_key(self, request):
        try:
            return json.loads(request.body)['api_key']
        except:
            return None

class InternalApiKeyAuthentication(CustomAuthenticationBase):
    def is_authenticated(self, request, **kwargs):
        if settings.INTERNAL_API_SECRET_KEY == self.get_api_key(request):
            return True
        logger.warning("IntenalApi: InternalApiKeyAuthentication, secret key authentication failed!, request:%s"% request)
        logger.debug("IntenalApi: InternalApiKeyAuthentication, settings.INTERNAL_API_SECRET_KEY: %s, api_key%s"%(settings.INTERNAL_API_SECRET_KEY, self.get_api_key(request)))
        return False

class urlencodeSerializer(Serializer):
    formats = ['json', 'urlencode']
    content_types = {
        'json': 'application/json',
        'urlencode': 'application/x-www-form-urlencoded',
    }
    def from_urlencode(self, data,options=None):
        """ handles basic formencoded url posts """
        qs = dict((k, v if len(v)>1 else v[0] )
            for k, v in urlparse.parse_qs(data).iteritems())
        return qs

    def to_urlencode(self,content): 
        pass

class StartMatchResource(ScorerResource):

    class Meta:
        resource_name = 'internal_start_match'
        allowed_methods = ['post']
        default_format = "application/json"
        serializer = urlencodeSerializer()
        authentication = InternalApiKeyAuthentication()
        
    def obj_create(self, bundle, **kwargs):
        response = deepcopy(constants.RESPONSE)
        
        match_id = bundle.data.get('match_id')
        logger.debug("IntenalApi: /internal_start_match/ called for match_id: %s"% match_id)
        if match_id:
            if not MSupervisor.is_r_dict_match(match_id):
                MSupervisor.start_match(match_id, False)
                response['status'] = True
                response['data'] = {'message': 'match started successfully!'}
            else:
                response['errors'].append('match is already started.')
        else:
            response['errors'].append('match_id is not present')
        return response
