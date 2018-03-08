#!/usr/bin/env python

# Python imports.
import logging
import os
import urllib

# Django imports.
from django.utils import simplejson

#GAE Imports
from google.appengine.api import taskqueue

#local import.
from controllers.base_controller import BaseRequestHandler
from controllers.base_controller import FacebookBaseHandler
from controllers import wrappers
from components import auth_component
from components import user_component
from components import media_component
from components import social_component
from lib import global_tools as gtools
from lib import gaesessions
from lib import constants
from lib import util
from lib import oauthclient
from lib import twitter
from lib import boto_lib

from model.connection import session

try:
  import webapp2 as webapp
except ImportError:
  from google.appengine.ext import webapp


class IndexPage(BaseRequestHandler):
  def get(self):    
    user =  util.get_active_user()
    if user:
      return self.redirect('/dashboard')
    page_vars = {}
    self.generate('index.html', page_vars)


class SignUp(BaseRequestHandler):
  @wrappers.log_params
  def get(self):
    response = self.request.get('response')
    user =  util.get_active_user()
    if user:
      if user.is_admin:
        return self.redirect('/admin/user_report')
      return self.redirect('/dashboard')
    self.redirect('/')
    return

  @wrappers.log_params
  def post(self):
   
    page_vars = {
                'email' : self.request.get('email', '').strip().lower(),
                'password' : self.request.get('password', '').strip(),
                'user_name' : self.request.get('user_name', '').strip(),
    }

    device_id = self.request.get('device_id','').strip()
    device_type = util.get_device_type(self.request)

    signup_response = user_component.signup_user(page_vars, device_id, device_type)
    if not signup_response['errors']:
      msg = 'You have successfully registered with Veromuse. Welcome mail has been sent to your registered Email.'
      self.redirect('/upload')
      return

    errors = signup_response['errors']
    if errors:
      self.redirect('/?errors=%s'%errors)
    self.redirect('/')
    return

class SignUpConfirm(BaseRequestHandler):
  @wrappers.log_params
  def get(self):
    data = {
        'user' : None
    }
    self.generate("signup_confirm.html", data )


class Login(BaseRequestHandler):
  @wrappers.log_params
  def get(self):
    user =  util.get_active_user()
    if user:
      if user.is_admin:
        return self.redirect('/admin/user_report')
      return self.redirect('/dashboard')
    pagevars = {
      'user':user
    }
    self.redirect('/')
    return

  @wrappers.log_params
  def post(self):
    continue_url = self.request.get('continue', '/dashboard')
    host = self.request.get('host')
    page_vars = {
      'email' : self.request.get('email', '').strip().lower(),
      'password' : self.request.get('password'),
      'device_id':'',
    }
    login_response = user_component.login_user(page_vars)
    if login_response['status']:
      user = util.get_active_user()
      if user.is_admin:
        continue_url = "/admin/user_report"
      self.redirect(util.get_http_domain()+continue_url)
      return

    self.redirect('/?err=1&email=%s' % urllib.quote_plus(page_vars['email']))
    return


class Logout(BaseRequestHandler):
  @wrappers.log_params
  def get(self):
    continue_url = self.request.get('continue', '/')
    session = gaesessions.get_current_session()
    if session.has_key('user_id'):
      session.terminate()
    self.redirect(continue_url)
    return


class Dashboard(BaseRequestHandler):
  @wrappers.log_params
  @wrappers.user_required
  def get(self, user=None):
    page_vars = {}
    self.generate('dashboard.html',page_vars)  
    
class ForgotUserName(BaseRequestHandler):
  @wrappers.log_params
  def get(self):
    user =  util.get_active_user()
    if user:
      return self.redirect('/dashboard')

    self.generate("forgot_username.html")

  @wrappers.log_params
  def post(self):    
    email = self.request.get('email')
    response = user_component.reset_username(email)
    data = {
        'email' : email,
        'response' : response,
        }
    logging.info(response)
    self.generate("forgot_username.html", data)
    
    
class ForgotPassword(BaseRequestHandler):
  @wrappers.log_params
  def get(self):
    user =  util.get_active_user()
    if user:
      return self.redirect('/dashboard')

    self.generate("forgot_password.html")

  @wrappers.log_params    
  def post(self):
    email = self.request.get('email')
    response = user_component.forget_password(email)
    data = {
        'email' : email,
        'response' : response,
        }
    self.generate("forgot_password.html", data )


class ResetPassword(BaseRequestHandler):
  @wrappers.log_params
  def get(self):
    user = util.get_active_user()
    response = None
    errors = None
    if user:
      util.delete_active_session(user = user)
    user_id = self.request.get('u_id')
    if user_id:
      user = util.get_user_by_id(user_id)
    token = self.request.get('token')
    if user_id and token:
      response = user_component.verify_reset_password(user, token)
      if response and not response['status']:
        response = simplejson.dumps(response)
        return self.redirect('/artists?response=%s'%response)

    if self.request.get('response'):
      response = simplejson.loads(self.request.get('response'))
    if response and response['errors']:
      errors = response['errors']
    data = {
        'user' : user,
        'errors':errors,
        'response':response
    }
    self.generate("reset_password.html", data )
    return 
  @wrappers.log_params
  def post(self):
    user_id = self.request.get('user_id')
    password = self.request.get('password')
    logging.info("  user id   ::  %s"%user_id)
    logging.info("  user password   ::  %s"%password)
    response = user_component.reset_password(user_id, password)
    if response['status']:
      response = simplejson.dumps(response)
      return self.redirect('/artists?response=%s'%response)
    else:
      response = simplejson.dumps(response)
      return self.redirect('/reset_password?response=%s&u_id=%s'%(response,user_id))

class RemoveAccount(BaseRequestHandler):
  @wrappers.log_params
  def get(self):
    user_id =  self.request.get('id')
    token = self.request.get('token')

    if user_id and token:
      response = user_component.remove_confirm(user_id, token)
      if not response['status']:
        response = simplejson.dumps(response)
        if util.get_active_user():
          return self.redirect('/dashboard?response=%s'%response)
        return self.redirect('/?response=%s'%response)

    page_vars = {
        'user' : None,
        'user_id':user_id,
        'token' : token
    }
    self.generate("remove_confirm.html", page_vars ) 
    return   

  @wrappers.log_params
  def post(self):
    user_id =  self.request.get('user_id')
    token = self.request.get('token')
    user_answer = int(self.request.get('user_answer'))
    logging.info(user_answer)
    page_vars = {
        'user' : None,
        'user_id' : user_id,
        'token':token,
        'user_answer' : user_answer
    }
    if user_answer == 1:
      response = user_component.deactivate_account(user_id, token)
      return self.redirect('/?response=%s'%simplejson.dumps(response))
    else:
      return self.redirect('/')    
    
class VerifyAccount(BaseRequestHandler):
  @wrappers.log_params
  def get(self):
    user_id =  self.request.get('id')
    token = self.request.get('token')

    response = user_component.verify_account(user_id, token)
    response = simplejson.dumps(response)
    user = util.get_active_user()
    if user:    
      return self.redirect('/dashboard?response=%s'%response)
    return self.redirect('/?response=%s'%response)


class SendInvitation(BaseRequestHandler):
  @wrappers.log_params
  @wrappers.user_required
  def get(self, user=None):
    page_vars = {
        'user':user,
        'status' : self.request.get('status', None),
        'msg' : self.request.get('msg'),
        "invite_emails" : util.get_invite_emails(user)  #Just to delete old emails those are saved in session.
    }
    self.generate("send_invite.html", page_vars)

  @wrappers.log_params
  @wrappers.user_required
  def post(self, user=None):
    email_addresses = self.request.get('email_addresses')
    page_vars = {
        'email_addresses': email_addresses.strip().lower().split(",")
    }
    response = user_component.send_invite(user, page_vars)
    page_vars['response'] = response

    logging.info(page_vars)  
    self.generate("send_invite.html", page_vars)


class CheckUserAvailability(BaseRequestHandler):
  def get(self):
    self.post()

  @wrappers.log_params
  def post(self, user=None):
    params = {
      'username':self.request.get('username','').strip(),
      'email':self.request.get('email','').strip().lower()
    }
    response = user_component.check_user_availability(params)
    status = True if response['status'] else False
    logging.info(response)
    self.json(status)
    return
    
class Settings(BaseRequestHandler):
  @wrappers.user_required
  @wrappers.log_params
  def get(self, user = None):
    response = self.request.get("response")
    is_popup =  gtools.str_to_bool(self.request.get("is_popup", "false"))
    logging.info(response)
    page_vars = {
      'user':user,
      'facebook_app_id' : constants.FACEBOOK_APP_ID,
      'response' : response,
      "is_popup" :is_popup,
    }
    self.generate("user_settings.html", page_vars)
    return

  @wrappers.user_required
  @wrappers.log_params    
  def post(self, user = None):
    register_follower = self.request.get("register_follower",'')
    if register_follower:
      register_follower = gtools.str_to_bool(register_follower)
    params = {
      'register_follower' : register_follower,
      'fb_toggle' : self.request.get("fb_toggle"),
      'twitter_toggle' : self.request.get("twitter_toggle"),
      'is_public' : gtools.str_to_bool(self.request.get("is_public")),
      'following_id' : self.request.get("following_id"),
      'unfollowing_id' : self.request.get("unfollowing_id"),
      'username' : self.request.get("username",'').strip(),
      'name' : self.request.get("name",'').strip(),
      'email' : self.request.get("email",'').strip().lower(),
      'password' : self.request.get("password",''),
      'profile_image' : self.request.get("profile_image",''),
      'fb_name' : self.request.get("fb_name",''),
      'twitter_name' : self.request.get("twitter_name",''),
      'playlist_name' : self.request.get("playlist_name",''),
      'passcode' : self.request.get("passcode"),
      'device_id' : self.request.get('device_id','').strip(),
      'playlist_toggle' : self.request.get("playlist_toggle"),
      'profile_picture_key' : self.request.get("profile_picture_key"),
      'party_name' : self.request.get("party_name",''),
      'is_unlisted' : gtools.str_to_bool(self.request.get("is_unlisted" ,"true")),
      'passcode' : self.request.get("passcode"),
      'playlist_ids' : self.request.get("playlist_ids"),
      'rescale_profile_picture_key' : self.request.get("rescale_profile_picture_key"),
      'facebook_user_permission' : self.request.get("facebook_user_permission", None),
    }

    name, username = None, None
    if self.request.get("name") != user.name:
      name = self.request.get("name").strip()
    if self.request.get("username") and self.request.get("username").strip() != user.username:
      username = self.request.get("username").strip() 

    names = self.request.get_all("name")
    if len(names) == 1:
      params["name"] = names[0].strip()
    response = user_component.edit_settings(user=user, params=params)
    logging.info(response)

    #if params['profile_picture_key'] and params['rescale_profile_picture_key']:
    #  user = user_component.change_profile_picture(user, params['profile_picture_key'], params['rescale_profile_picture_key'])
    #  #profile_image = boto_lib.get_image_url(s3_bucket=constants.USER_IMAGES_BUCKET, s3_key=user.s3_image_key)
    if response['status']:
      user_component.notification_for_update_settings(user, constants.UPDATE_USER_SETTINGS, profile_image=None, name=name, username=username)
    if gtools.str_to_bool(self.request.get('json_required',"false")):
      self.json(response)
      return
      
    session.refresh(user)
    page_vars = {
      'response' : response,
      'user':user
    }
    self.generate("user_settings.html", page_vars)
    return
    

class FacebookLogout(FacebookBaseHandler):
  def get(self):
    if self.current_user is not None:
        self.session['user'] = None

    self.redirect('/settings')
   
    
class SignInWithTwitter(webapp.RequestHandler):
    def get(self):

        key, secret = oauthclient.retrieve_service_request_token(constants.TWITTER_REQUEST_TOKEN_URL,
                                                                 constants.TWITTER_CONSUMER_KEY,
                                                                 constants.TWITTER_CONSUMER_SECRET)
        session = gaesessions.get_current_session()
        session['twitter_request_key'] = key
        session['twitter_request_secret'] = secret
        logging.info( oauthclient.generate_authorize_url(constants.TWITTER_AUTHENTICATE_URL, key))  
        self.redirect(oauthclient.generate_authorize_url(constants.TWITTER_AUTHENTICATE_URL, key))
        
class TwitterCallbackUrl(BaseRequestHandler):
  @wrappers.user_required
  def get(self, user = None):
    response = None
    twitter_oauth_token = self.request.get("oauth_token")
    twitter_oauth_verifier = self.request.get("oauth_verifier")
    logging.info("/twitter_authorised?oauth_verifier=%s&oauth_token=%s"%(twitter_oauth_verifier, twitter_oauth_token))
    self.redirect("/twitter_authorised?oauth_verifier=%s&oauth_token=%s"%(twitter_oauth_verifier, twitter_oauth_token))
    return
    
class TwitterAuthorized(webapp.RequestHandler):
  @wrappers.user_required
  def get(self, user=None):
    
    session = gaesessions.get_current_session()
    params = {
          'verifier' : self.request.get("oauth_verifier"),
          'key' : session.get('twitter_request_key'),
          'secret' : session.get('twitter_request_secret')
    }
    response = user_component.twitter_user_settings(user=user, params=params)
    response = simplejson.dumps(response)
    self.redirect("/settings?response=%s&is_popup=%s"%(response,True))
    return

class FacebookCallbackUrl(BaseRequestHandler):
  def get(self):
    
    hub_mode = self.request.get('hub.mode')
    hub_challenge = int(self.request.get('hub.challenge'))
    hub_verify_token = self.request.get('hub.verify_token')

    self.json(hub_challenge)
    return 
    
  def post(self):
    response = {}
    task_params = {}
    logging.info(self.request.body)
    form_elements = simplejson.loads(self.request.body)
    user_object = form_elements['object']
    user_entries = form_elements['entry']
    if user_object == "user":
      for entry in user_entries:
        logging.info(entry['changed_fields'])
        if entry['changed_fields'] and 'friends' in entry['changed_fields']:        
          task_params['facebook_id'] = entry['uid']

      if task_params:
        taskqueue.add(url='/tasks/update_facebook_note_friends',
                      queue_name='update-facebook-note-friends',
                      params=task_params)

    self.json(response)
    return
    
class SetUserImage(BaseRequestHandler):
  def get(self):
    response =user_component.set_user_image()
    self.json(response)

class FBPostRedirect(BaseRequestHandler):
  def get(self, token_info=None):
    if token_info:
      token_detail = util.get_detail_of_token(token_info)
      self.content_id = token_detail["content_id"] if token_detail.has_key("content_id") else None
      self.post_user_id = token_detail["post_user_id"] if token_detail.has_key("post_user_id") else None
      self.token = token_detail["token"] if token_detail.has_key("token") else None
      self.post_message = None
    else:
      self.content_id = self.request.get("content_id", None)
      self.post_user_id = self.request.get("post_user_id", None)
      self.token = self.request.get('token', None)
      self.post_message = self.request.get("post_message", None)

    check_valid = self.check_valid_request()
    if not check_valid:
      self.error(404)
      return

    if not self.post_message:
      self.post_message = self.auth_token.message

    user = util.get_active_user()

    follower_ids = util.get_followers_ids(user) if user else []
    split_s3_key = str(self.content.s3_Key).split(".")
    c_format = split_s3_key[-1]
    logging.info("content url format  :: %s"%c_format)
    logging.info("content format  :: %s"%self.content.format)
    content_format = "mp3" if self.content.format == "mp3" and c_format == "mp3" else "mp4"
    content_streaming_url = "rtmp://%s/vods3/_definst_/%s:amazons3/%s/%s"%(constants.EC2_DOMAIN_URL, content_format, constants.DEFAULT_BUCKET_NAME, self.content.s3_Key)
    logging.info("content url  :: %s"%content_streaming_url)
    post_album_image = boto_lib.get_image_url(constants.ALBUM_IMAGES_BUCKET, self.content.album.s3_fb_post_image_key) if self.content.album.s3_fb_post_image_key else None

    domain_url = util.get_domain()
    favicon_image_url = domain_url + constants.DEFAULT_VEROMUSE_LOGO
    page_vars = {
      'user' : user,
      'post_user' : self.post_user,
      'content' : self.content,
      'content_streaming_url' : content_streaming_url,
      's3_content_con_url' : util.get_s3_host_url(constants.DEFAULT_BUCKET_NAME),
      's3_user_con_url' : util.get_s3_host_url(constants.USER_IMAGES_BUCKET),
      'post_album_image' : post_album_image,
      'is_following' : True if self.post_user.id in follower_ids else False,
      'ios_app_link': constants.APPLE_STORE_LINK,
      'play_store_link':constants.PLAY_STORE_LINK,
      'facebook_app_id' : constants.FACEBOOK_APP_ID,
      'post_message' : self.post_message if self.post_message else '',
      "link_url" :self.request.url,
      "favicon_image_url": favicon_image_url,
      "facebook_meta_image" : post_album_image if post_album_image else favicon_image_url,
      "facebook_meta_image_height": constants.FB_POST_IMAGE_HEIGHT if post_album_image else constants.DEFAULT_VLOGO_HEIGHT,
      "facebook_meta_image_width": constants.FB_POST_IMAGE_WIDTH if post_album_image else constants.DEFAULT_VLOGO_WIDTH,
      "google_play_app_id" : constants.GOOGLE_PLAY_APP_ID,
      "apple_store_app_id" : constants.APPLE_STORE_APP_ID,
      'mega_tag_description' : constants.META_TAG_DESCIPTION,
      'mega_tag_robots' : constants.META_TAG_ROBOTS,
      'mega_tag_keywords' : constants.META_TAG_KEYWORDS
    }
    self.generate("facebook_post_redirect.html", page_vars)
    return

  def check_valid_request(self):
    if not (self.content_id and self.post_user_id and self.token):
      return False
  
    self.content = util.get_content_by_id(int(self.content_id))
    self.post_user = util.get_user_by_id(int(self.post_user_id))
    if not (self.content and self.post_user):
      return False

    response = auth_component.validate_token(self.token, self.post_user, self.content)
    logging.info(response)
    if not response['status']:
      return False

    self.auth_token = response['data']['auth_token']
    return True

class FacebookSync(BaseRequestHandler):
  @wrappers.log_params
  @wrappers.user_required
  def post(self, user=None):
    facebook_token = self.request.get("facebook_token",None)
    response = user_component.facebook_account_sync(user, facebook_token)
    self.redirect('/settings')
    return
