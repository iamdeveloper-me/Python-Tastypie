#!/usr/bin/env python
import json
import logging

# Local imports
from lib import constants
from lib import global_tools as gtools
from lib import util
from lib import gaesessions

"""

  If a developer adds a decorator to require something but forgets
  to put in a keyword arg in the function parameters, we'd get a
  TypeError exception and a callstack that fails to include the
  file and/or class with the issue.

  Catch the exception here so we can log the module/class/method.

"""
def _call_method(wrapper, method, *args, **kwargs):
  result = None
  try:
    result = method(wrapper, *args, **kwargs)
  except TypeError, e:
    if 'unexpected keyword' in str(e) and method.__name__ != 'wrapper':
      logging.error("Make sure %s.%s.%s() declares all wrapper generated keyword arguments.",
                    wrapper.__class__.__module__, wrapper.__class__.__name__, method.__name__)
    raise
  return result

def log_params(method):
  """Logs GET/POST parameters."""
  def wrapper(self, *args, **kwargs):
    logging.debug('Parameters:')
    arguments = self.request.arguments()
    try:
      for argument_name in arguments:
        if not argument_name in ['image_file','profile_image', 'file', 'password']: # TODO Add password in list.
          values = self.request.get_all(argument_name)
          for value in values:
            logging.debug('%s = %s' % (str(argument_name), str(value)))

      # all done, carry on with normal function execution
    except Exception:
      pass
    return _call_method(self, method, *args, **kwargs)

  return wrapper

def api_current_user_required(method):
  def wrapper(self, *args, **kwargs):
    user = None
    user_id = self.request.get('user_id')
    if user_id :
      user = util.get_user_by_id(user_id, load_only_params=False)
    else:
      user = util.get_active_user(load_only_params=False)

    if not user:
      logging.info("UserAuthenticationRequired")
      self.error(403)
      data = {'status': False, 'errors':{'error': 'UserAuthenticationRequired'}}
      self.json(data)
      return
    kwargs['user'] = user
    logging.info("logged in user  ::   %s"%user.username)
    return _call_method(self, method, *args, **kwargs)
  return wrapper


def api_user_required(method):
  def wrapper(self, *args, **kwargs):
    user = None
    user_id = self.request.get('user_id')
    if user_id :
      user = util.get_user_by_id(user_id, load_only_params=True)
    else:
      user = util.get_active_user()

    if not user:
      logging.info("UserAuthenticationRequired")
      self.error(403)
      data = {'status': False, 'errors':{'error': 'UserAuthenticationRequired'}}
      self.json(data)
      return
    kwargs['user'] = user
    logging.info("logged in user  ::   %s"%user.username)
    return _call_method(self, method, *args, **kwargs)
  return wrapper

def user_required(method):
  def wrapper(self, *args, **kwargs):
    user = None
    user_id = self.request.get('user_id')
    json_required = gtools.str_to_bool(self.request.get('json_required', 'false'))
    if user_id :
      user = util.get_user_by_id(user_id)
    else:
      user = util.get_active_user()

    if not user:
      logging.error("Not an authorised user")
      if json_required:
        response = {
            "status" : constants.ERROR,
            "data" : None,
            "errors" : {"msg":"unauthorized user", "error":"E403"}
        }
        self.json(response)
        return
      else:
        self.redirect("/artists")
        return

    kwargs['user'] = user
    logging.info("logged in user  ::   %s"%user.username)    
    return _call_method(self, method, *args, **kwargs)
  return wrapper


def api_key_required(method):
  def wrapper(self, *args, **kwargs):
    secret_key = self.request.get('secret_key')
    if secret_key == constants.SECRET_API_KEY:
      pass
    else:
      logging.info("SecretKeyRequired")
      self.error(403)
      data = {'status': False, 'errors':{'error': 'SecretKeyRequired'}}
      self.json(data)
      return
    return _call_method(self, method, *args, **kwargs)
  return wrapper


# TODO: improve logic
def admin_access_required(method):
  """Decorator for restricting admin access."""
  def wrapper(self, *args, **kwargs):
    user = util.get_active_user()
    if user:
      is_admin = user.is_admin
      if is_admin:
        kwargs['user'] = user
        return _call_method(self, method, *args, **kwargs)
    msg = 'Admin access required'
    logging.error(msg)
    self.error(403)
    self.redirect("/dashboard?error_message=%s"%msg)
    return

  return wrapper

def parse_device_detail(method):
  def wrapper(self, *args, **kwargs):
    notification_enable = gtools.str_to_bool(self.request.get('notification_enable', "true"))
    device_id = self.request.get('device_id')
    device_type = util.get_device_type(self.request)
    kwargs['device_id'] = device_id
    kwargs['device_type'] = device_type
    kwargs['notification_enable'] = notification_enable
    return _call_method(self, method, *args, **kwargs)
  return wrapper
  
def parse_device_and_protocol_details(method):
  def wrapper(self, *args, **kwargs):
    session = gaesessions.get_current_session()
    device_type = session['device_type']
    protocol = constants.DEFAULT_STREAMING_PROTOCOL
    if device_type == "ios":
      protocol = self.request.get("protocol", constants.APPLE_STREAMING_PROTOCOL)
    elif device_type == "android":
      protocol = self.request.get("protocol", constants.ANDROID_STREAMING_PROTOCOL)
    else:
      protocol = self.request.get("protocol", constants.DEFAULT_STREAMING_PROTOCOL)

    kwargs['protocol'] = protocol
    session['protocol'] = protocol
    session.save()
    
    return _call_method(self, method, *args, **kwargs)
  return wrapper

def playlist_required(method):
  def wrapper(self, *args, **kwargs):
    playlist_id = None
    if self.request.route_args and self.request.route_args[0]:      
      playlist_id = int(self.request.route_args[0])

    logging.info("Playlist id :: %s" %playlist_id)

    if playlist_id:
      playlist = util.get_playlist_by_id(int(playlist_id))
      if playlist:
        kwargs['playlist'] = playlist
        return _call_method(self, method, *args, **kwargs)

    logging.info("Error 404 : invalid playlist id.")
    self.error(404)
    self.json({'status':False, 'data':None, 'errors':{'error':constants.INVALID_VALUE}})
    return
  return wrapper

def content_required(method):
  def wrapper(self, *args, **kwargs):
    content_id = self.request.get("content_id", None)
    
    logging.info("content id :: %s" %content_id)

    if content_id:
      content = util.get_content_by_id(int(content_id))
      if content:
        kwargs['content'] = content
        return _call_method(self, method, *args, **kwargs)

    logging.info("Error 404 : invalid content id.")
    self.error(404)
    self.json({'status':False, 'data':None, 'errors':{'error':constants.INVALID_VALUE}})
    return
  return wrapper
