#!/usr/bin/env python

#Python import.
import logging
import os
import datetime 
import operator
import base64

#AppEngine imports.
from google.appengine.api import images as gap_image
from google.appengine.api.images import NotImageError
from google.appengine.api import taskqueue
from google.appengine.ext import db
from google.appengine.api import urlfetch
from google.appengine.ext import blobstore
from google.appengine.api import images
from google.appengine.api.datastore import Key

# Django imports.
from django.utils import simplejson

#Local import.
from lib import auth
from lib import gaesessions
from lib import facebook
from lib import util
from lib import global_tools as gtools
from lib import constants
from components import auth_component
from components import media_component
from components import media_activity_component
from components import launch_activity_component
from components import search_component
from components import party_component
from components import playlist_component
from components import playlist_component
from components import social_component

from ds_components import ds_post_component
from ds_components import ds_user_component
from ds_components import ds_content_component
#model import.
from model.connection import session
from model import models as model
from model.schema import *
from lib import api_serialize
from lib import oauthclient
from lib import twitter
from lib import boto_lib

#sqlalchemy imports.
from sqlalchemy import update
from sqlalchemy import insert
from sqlalchemy import delete
from sqlalchemy.sql import or_
from sqlalchemy.sql import and_
from sqlalchemy.sql import desc
from sqlalchemy.sql import func
from sqlalchemy.orm import load_only, Load
from sqlalchemy.orm import joinedload
from sqlalchemy.orm import aliased

def delete_user_detail(user_id):
  response = {
    "status" : constants.ERROR,
    "errors" : None,
    "data" : None
  }
  user = util.get_user_by_id(user_id)
  if not user:
    response["errors"] = {"error": "User not found."}
    return response

  taskqueue.add(url='/tasks/hard_delete_user',
            method='POST',
            queue_name='optimize-queue',
            params={ 'user_id': user_id}
            )
  response["data"] = {"msg" : "Your deletion request is registered. User will be deleted after some time."}
  return response

def signup_user(params, device_id=None, device_type=None, ios_env=None):

    errors = validate_user_form(params)
    response = {}

    logging.info( errors)
    try:
      if not errors :
        signup_by = util.get_user_signup(device_type)

        user_obj = model.User()
        user_obj.username = params['user_name']
        user_obj.email = params['email']
        user_obj.password = auth.encrypt_password(params['password'])
        user_obj.user_type = 0                  # normal user define
        user_obj.added_date = datetime.datetime.now()
        user_obj.is_email_verified = False
        if signup_by == constants.WEB_SIGNUP:
          user_obj.is_first_device_login = True
        else:
          user_obj.is_first_device_login = False
        user_obj.is_followup_email_sent = 0
        user_obj.is_verification_required = constants.DEFAULT_VERIFICATION_REQUIRED
        user_obj.is_launch_complete = True
        user_obj.cluster_id = None
        user_obj.add_playlist_toggle = False
        user_obj.playlist_id = None
        if device_type:
          user_obj.signup_by = signup_by

        session.add(user_obj)
        session.flush()
        session.commit()

        session.refresh(user_obj)
        auth_token = auth_component.create_auth_token(user=user_obj, is_expires=False )
        util.save_profile_image(user_obj)
        search_component.update_user_document(user_obj)
        
        taskqueue.add(url='/tasks/blur_user_image',
                  method='GET',
                  queue_name='blur-user-image',
                  params={ 'user_id': user_obj.id}
                  )
        
        register_follower(follower_user= user_obj, following_user_id=None)

        deactive_url = '%s/remove_account?id=%s&token=%s'%(util.get_domain(), user_obj.id, auth_token.token)
        verify_url = '%s/verify_account?id=%s&token=%s'%(util.get_domain(), user_obj.id, auth_token.token)

        logging.info(deactive_url)
        logging.info(verify_url)

        email_response = signup_welcome(user_obj, deactive_url, verify_url)
        logging.info("  Send Welcome email Response     ::    %s"% email_response)

        gae_session = gaesessions.get_current_session()
        if gae_session.is_active():
          gae_session.terminate()

        gae_session['user_id'] = int(user_obj.id)
        gae_session['email'] = user_obj.email
        gae_session['device_id'] = device_id
        gae_session['device_type'] = device_type
        gae_session['ios_env'] = ios_env
        gae_session.save()

        #if not user_obj.is_verification_required:
        #util.check_and_update_for_reserve_spot(user_obj)
       
        data = {
          'user':[{
                'id':user_obj.id,
                'user_type' : user_obj.user_type,
                'username': user_obj.username,
                'email':user_obj.email,
                'profile_image': util.get_full_image_url(user_obj, constants.USER_IMAGES_BUCKET),
                'blur_profile_image' : util.get_full_blur_image_url(user_obj, constants.USER_IMAGES_BUCKET),
                'blur_short_image' : util.get_short_blur_image_url(user_obj, constants.USER_IMAGES_BUCKET),
                'profile_short_image' : util.get_short_image_url(user_obj, constants.USER_IMAGES_BUCKET),
                'is_verification_required' : user_obj.is_verification_required,
                'is_first_device_login' : True,
                'launch_video_url' : util.get_launch_video_url(device_type)
          }],
        }
        response = {
          'errors': None,
          'status': constants.SUCCESS,
          'data': data
        }
        logging.info("signup response ::   %s"%response)        
        return response

      response = {
        'errors':errors,
        'data': None,
        'status': constants.ERROR
      }
      logging.info("signup response ::   %s"%response)
      
    except Exception as e :
      logging.exception(e)
      response =  {
                   "status": constants.ERROR,
                   "data": {},
                   "errors": {"error":"Failed to fetch data from database."}       
                 }  

    return response

def validate_user_form(params):
  errors = {}
  logging.info(params)
  if not util.validate_email(params['email']):
    errors['email'] = 'Please Enter valid Email'
    logging.info('--Invalid  EMAIL--  %s'% params['email'])

  if not params['email']:
    errors['email'] = 'Please Enter Email.'

  if not params['user_name']:
    errors['username'] = 'Please Enter Username.'
  else:
    if " " in params['user_name']:
      errors['username'] = 'space not allowed.'
  
    if len(params['user_name'])<4 or len(params['user_name'])>30:
      errors['username'] = 'Username should be between 4 and 30 characters.'
      
    if not util.validate_username(params['user_name']):
      errors['username'] = 'alphanumeric and underscore allowed only.'

  if not params['password']:
    errors['password'] = 'Please Enter Password.'
  else:
    if len(params['password']) < 8:
      errors['password'] = 'Password length should be atleast 8 characters.'

  if params['email']:
    user = util.get_user_by_email(params['email'])
    if user:
      errors['email'] = 'Email already exists.'
  if params['user_name']:    
    user_by_name = util.get_user_by_name(params['user_name'])
    if user_by_name:
      errors['username'] = 'Username is already taken.'

  return errors 

def signup_welcome(user, deactive_url, verify_url):
  response = {}
  if user:
    util.send_welcome_email(user, deactive_url, verify_url)
    response['status'] = constants.SUCCESS
    response['data'] = {"msg":'successfully send user name in your email.'}
  else:
    response['status'] = constants.ERROR
    response['data'] =  {"msg":'Email not found in the database.'}
  return response

def login_user(page_vars, device_id=None, device_type=None, is_mobile=True, ios_env=None):
  email = page_vars['email']
  password = page_vars['password']
  response = {}
  
  response['status'] = constants.ERROR
  response['data'] = None
  try:        
    if email and password:
      user = util.get_user_by_email(email, False)
      if not user:
        user = util.get_user_by_name(email)
      if user:
        if user.is_active == 1:
          if device_id:
            gaesessions.flush_session_by_device_id(device_id)

          user, is_first_device_login = util.login(email, password, device_id, device_type, ios_env)
          if user:
            if is_mobile:
              data = {
                  'artist_count' : util.artist_count(),
                  'user': [{
                      'id':user.id,
                      'user_type':user.user_type,
                      'username' : user.username,
                      'name' : user.name,
                      'profile_image': util.get_full_image_url(user, constants.USER_IMAGES_BUCKET),
                      'blur_profile_image' : util.get_full_blur_image_url(user, constants.USER_IMAGES_BUCKET),
                      'blur_short_image' : util.get_short_blur_image_url(user, constants.USER_IMAGES_BUCKET),
                      'profile_short_image' : util.get_short_image_url(user, constants.USER_IMAGES_BUCKET),
                      'contact_number' : user.contact_number,
                      'is_launch_complete' : user.is_launch_complete,
                      'is_sync_contacts' : user.is_sync_contacts,
                      'is_verification_required' : user.is_verification_required,
                      'is_first_device_login' : is_first_device_login,
                      'launch_video_url' : util.get_launch_video_url(device_type),
                      'email' : user.email,
                      'is_email_verified' : user.is_email_verified,
                  }],
              }
            else:
              data = {"is_admin": user.is_admin, "user_id":int(user.id)}
            response['status'] = constants.SUCCESS
            response['errors'] = None
            response['data'] = data
          else:
            response['errors'] = {'password':constants.INVALID_VALUE, "msg": constants.INVALID_LOGIN_MSG}
        else:
          response['errors'] = {'email':constants.SUSPEND_CODE, "msg": constants.SUSPENDED_USER_LOGIN_MSG}
      else:
        response['errors'] = {'email':constants.INVALID_VALUE, "msg": constants.INVALID_LOGIN_MSG}
        
    logging.info("Login response  ::  %s"%response)
  except Exception as e :
    logging.exception(e)
    response['errors'] = {"error":"Failed to fetch data from database."}
  return response

def reset_username(email, is_mobile=False):
  response = {}
  response['status'] = constants.ERROR
  if email:
    if util.validate_email(email):
      user = util.get_user_by_email(email)
      if user:
        if user.is_active:
          util.reset_username_email(user)
          response['status']  = constants.SUCCESS
          response['data'] = {'msg':'Email successfully sent with Username.'}
          if is_mobile:
            response['errors'] = None
            response['data'] = None
        else:
          response['data'] = {'msg':'Account Temporary Deactivated.'}
      else:
        response['data'] = {'msg':'Email not registered.'}
    else:
      response['data'] = {'msg':'Please Enter Valid Email.'}
  else:
      response['data'] = {'msg':'Missing Email.'}
      
  if is_mobile and not response['status']:
      response['errors'] = {'email':'E002'}
      response['data'] = None

  return response

def forget_password(email, is_mobile=False):
  response = {
      "status" : constants.ERROR,
      "errors":None,
      "data":None
  }
  errors = {}
  if email:
    if util.validate_email(email):
      user = util.get_user_by_email(email)
      
      if user:
        if user.is_active:

          randomnumber = util.random_number()
          token = auth.encrypt_password(randomnumber)

          auth_token = model.OAuthToken()
          auth_token.token = token
          auth_token.user_id = user.id

          session.add(auth_token)
          session.flush()
          session.commit()

          password_reset_url = '%s/reset_password?u_id=%s&token=%s'%(util.get_domain(), int(user.id), token)          
          logging.info('   Auth Token    ::  %s'% token)
          util.reset_password_email(user, password_reset_url)
          response['status'] = constants.SUCCESS
          response['data'] = {'msg':'Email successfully sent with reset password link.'}
          return response
        else:
          errors['msg'] = 'Account temporary deactivated.'
      else:
        errors['msg'] = 'Email not registered.'
    else:
      errors['msg'] = 'Please enter a valid email.'
  else:
      errors['msg'] = 'Please enter your email.'

  response['errors'] = {'email':'E002'} if is_mobile else errors
  return response

def reset_password(user_id, password):
  response = {
    "status" : constants.ERROR,
    "errors" : None,
    "data" : None
  }
  try:
    errors = {}
    user = util.get_user_by_id(user_id)
    if not (user_id and password):
      response['data'] = {'msg':'Result not found for given details.'}
      return response

    if password:
      if len(password) < 8:
        errors['password'] = 'Password should be at least 8 characters long.'
    else:
      errors['password'] = 'Please enter a password.'
    logging.info(errors)
    if errors:
      response["errors"] = errors
      return response

    encrypt_password = auth.encrypt_password(password)
    user.password=encrypt_password
    session.commit()

    logging.info("--  updated user successfully --")
    response['status'] = constants.SUCCESS
    response['data'] =  {'msg':'Your password changed successfully.'}
  except Exception as e:
    logging.exception(e)
    response['data'] = {"msg":constants.SOMETHING_WRONG_MSG}
  return response
  
def deactivate_account(user_id, token):
  response = {
    "status" : constants.ERROR,
    "data":None,
    "errors":None,
  }
  try:
    user = util.get_user_by_id(user_id)
    if not user:
      response['data'] = {"msg":'User not found for the given detail.'}
      return response

    if not user.is_active:
      response['data'] = {"msg":'You have already requested for deletion.'}
      return response

    auth_token = session.query(model.OAuthToken).filter(model.OAuthToken.token == token).\
                                  filter(model.OAuthToken.user_id == user.id).first()
    if not auth_token:
      response['data'] = {"msg":'This link is expired.'}
      return response

    auth_component.delete_auth_token(token, user)
    user.is_active=False
    session.commit()

    taskqueue.add(
      url='/tasks/notification_for_suspend_user',
      method='GET',
      queue_name='send-notifiation-to-device',
      params={'user_id': user_id}
    )
    email_response = util.send_admin_delete_mail(user)

    gae_session = gaesessions.get_current_session()
    if gae_session.is_active():
      gae_session.terminate()

    gaesessions.freez_all_other_sessions_by_user(user_id)

    logging.info("  Sending admin email for Delete Account :: %s"% email_response)
    response['status'] = constants.SUCCESS
    response['data'] = {"msg":'Your account has been deactivated successfully.'}

  except Exception as e:
    logging.exception(e)
    response['data'] = {"msg":constants.SOMETHING_WRONG_MSG}
  return response

def remove_confirm(user_id, token):
  response = {
    "status" : constants.ERROR,
    "data":None,
    "errors":None,
  }
  try:
    user = util.get_user_by_id(user_id)
    if not user:
      response['data'] = {"msg":'User not found for the given detail.'}
      return response

    if not user.is_active:
      response['data'] = {"msg":'You have already requested for deletion.'}
      return response

    auth_token = session.query(model.OAuthToken).filter(model.OAuthToken.token == token).\
                                  filter(model.OAuthToken.user_id == user.id).first()
    if not auth_token:
      response['data'] = {"msg":'This link is expired.'}
      return response

    logging.info( "auth_token  ID :: %s"%auth_token.id)
    response['status'] = constants.SUCCESS
    response["data"] = {"msg":'Your account has been deleted successfully.'}

  except Exception as e:
    logging.exception(e)
    response['data'] = {"msg":constants.SOMETHING_WRONG_MSG}
  return response

def verify_account(user_id, token):
  response = {
    "status" : constants.ERROR,
    "data" : None,
    "errors":None
  }
  try:
    logging.info("user id ::  %d and token :: %s  " %(int(user_id),  token))
    user = util.get_user_by_id(user_id)
    if not user:
      response['data'] = {'msg':'User not found for the given detail.'}
      return response

    if not user.is_active:
      response['data'] = {'msg':'Your account is deactivated. Please contact to the support.'}
      return response

    if user.is_email_verified:
      response["status"] = constants.SUCCESS
      response["data"] = {"msg":"Email is already verified."}
      if token and user:
        auth_component.delete_auth_token(token, user)
      return response

    auth_token = session.query(model.OAuthToken).filter(model.OAuthToken.token == token).\
                                  filter(model.OAuthToken.user_id == user.id).first()
    if not auth_token:
      response['data'] = {'msg':'This link is expired.'}
      return response

    user.is_active=True
    user.is_email_verified=True
    user.is_verification_required=False
    if session.is_modified(user):
      session.merge(user)
      session.flush()
      session.commit()

    #if not user.cluster_id:
    #  util.check_and_update_for_reserve_spot(user)
    auth_component.delete_auth_token(token, user)
    response['status'] = constants.SUCCESS
    response["data"] = {"msg":'Your account has been Verified successfully.'}

  except Exception as e:
    logging.exception(e)
    response['data'] = {'msg':constants.SOMETHING_WRONG_MSG}
  return response

def verify_reset_password(user, token):
  response = {
      'errors':None
  }
  if user and token:
    auth_token = session.query(model.OAuthToken).filter(model.OAuthToken.token == token).\
                                  filter(model.OAuthToken.user_id == user.id).first()

    if auth_token:
      auth_component.delete_auth_token(token, user)
      logging.info(" -- Auth token is deleted -- ")
      response['status'] = constants.SUCCESS
      response['data'] = {'msg':'Please reset the password.'}
    else:
      response['status'] = constants.ERROR
      response['data'] =  {'msg':'This link is expired.'}
  logging.info(response)
  return response

def send_invite(user, page_vars):
  response = {
    "status" : constants.ERROR,
    "errors" : None,
    "data" : None,
  }

  if not page_vars['email_addresses']:
    response["data"] = {"msg": 'Please enter atleast one email.'}
    return response

  email_addresses = map(lambda x:x.strip(), page_vars['email_addresses'])
  logging.info(email_addresses)
  emails = [email for email in email_addresses if util.validate_email(email)]
  if not emails:
    response["data"] = {"msg": 'Please enter atleast one valid email.'}
    return response

  fan_list = []
  for email in emails:
    exist_email = util.get_user_by_email(email)
    if exist_email:
      util.send_invitaion_mail(email, user, is_exist = True, exist_user_name=exist_email.username)
    else :
      util.send_invitaion_mail(email, user, is_exist = False)
    fan_list.append({'user_id':user.id,'email':email, 'added_date':datetime.datetime.now()})

  query = fan_list_table.insert().values(fan_list)
  session.execute(query)
  session.flush()
  session.commit()
  logging.info("Email has been added on the database for following entries")  
 
  response['data'] = {'msg':"Great! We've sent invitations to your fans!"}
  response['status'] = constants.SUCCESS
  return response

def edit_setting(user, params):
  name = params['name']
  username = params['username']
  email = params['email']
  fb_name = params['fb_name']
  twitter_name = params['twitter_name']
  password = params['password'] 
  profile_picture = params['profile_picture']
  
  errors = client_validation_editsettings(user, params)
  status = constants.ERROR
  response = {}
  if errors:
    response['errors'] = errors
    response['status'] = status
  else:
    if user:
      picture_key = None
      image_url = user.image_url
      if profile_picture:
        s3_key = str(util.get_unique_key()) +"_"+ user.id +".png"
        image_url = boto_lib.save_img_in_s3(profile_picture, s3_key, s3_bucket)

      update_user = update(user_table).where(user_table.c.id==user.id ).values(
        fb_name= fb_name ,
        twitter_name = twitter_name ,
        username = username ,
        name = name ,
        email = email, 
        password = auth.encrypt_password(password) ,
        image_url = image_url
      )

      session.execute(update_user)
      session.flush()
      session.commit()
      user_obj = {
          'username' : username,
          'email' : email,
          'fb_name' : fb_name,
          
      }
      
      data = {
          'user': user_obj,
          'msg':'user profile has been updated successfully.',
      }
      status = constants.SUCCESS
      response['status'] = status
      response['data'] = data
  logging.info("edit settings response ::  %s"%response)
  return response

def client_validation_editsettings(user, params, is_mobile):
  errors = {}
  if params['username']:
    if " " in params['username']:
      errors['username'] = 'space not allowed.'
  
    if len(params['username'])<4 or len(params['username'])>30:
      errors['username'] = 'Username should be between 4 and 30 characters.'

  if params['password']:
    if len(params['password']) < 8:
      errors['password'] = 'Password length should be atleast 8 characters.'

  if params.has_key("name") and params['name'] and '@' in params['name']:
    errors['name'] = '@ not allowed.'
  logging.info(errors)
  if is_mobile and errors.has_key("password"):
    errors['password'] = constants.INVALID_VALUE
  if is_mobile and errors.has_key("username"):
    errors['username'] = constants.INVALID_VALUE
  if is_mobile and errors.has_key("name"):
    errors['name'] = constants.INVALID_VALUE
  return errors 

def server_validation_editsettings(user, params, is_mobile):
  errors = {}
  if params['email'] and not util.validate_email(params['email']):
    if is_mobile:
      errors['email'] = 'E002'
    else:
      errors['email'] = 'Please Enter Valid Email.'
    logging.info('--Invalid  EMAIL--   :: %s'% params['email'])

  if params['email']:
    if user.email != params['email']:
      user_by_email = session.query( model.User ).\
                            filter( model.User.email == params['email']).\
                            filter( model.User.id != user.id ).first()
      if user_by_email:
        if is_mobile:
          errors['email'] = constants.ALREADY_EXISTS
        else:
          errors['email'] = "Email already exists."
        
  if params['username']:
    if not util.validate_username(params['username']):
      if is_mobile:
        errors['username'] = 'E002'
      else:
        errors['username'] = 'alphanumeric and underscore allowed only.'
    
    if user.username != params['username']:
      user_by_name = session.query( model.User ).\
                            filter( model.User.username == params['username']).\
                            filter( model.User.id != user.id ).first()
      if user_by_name:
        if is_mobile:
          errors['username'] = constants.ALREADY_EXISTS
        else:
          errors['username'] = "Username already exists."
     
  party_name =  params['party_name']
  playlist_name = params['playlist_name']

  if party_name:
    if params['is_unlisted'] and not params['passcode']:
      errors['passcode'] = constants.PARAM_REQUIRED
    else:
      party = session.query( model.Party ).\
                              filter( model.Party.name == party_name).\
                              filter( model.Party.user_id == user.id ).first()
      if party:
        errors['party'] = constants.ALREADY_EXISTS
    
  if playlist_name:
    playlist = session.query( model.Playlist ).\
                            filter( model.Playlist.name == playlist_name).\
                            filter( model.Playlist.user_id == user.id ).first()
    if playlist:
      errors['playlist'] = constants.ALREADY_EXISTS

  if params['profile_image']:
    try:
      img_height = gap_image.Image(image_data= params['profile_image']).height
    except gap_image.NotImageError:    
      logging.info("not a valid image format.")
      if is_mobile:
        errors['profile_image'] = 'E002'
      else:
        errors['profile_image'] = 'Invalid Image file Format.'
    except Exception as e:
      logging.exception(e)
      if is_mobile:
        errors['profile_image'] = 'E002'
      else:
        errors['profile_image'] = 'Invalid Image file Format.'
      pass
  logging.info(errors)
  return errors
  
def check_user_availability(params):
  username = params['username']
  email = params['email']
  response = {}
  errors = {}
  msg = None
  if username:
    user_by_name = session.query(model.User).filter(model.User.username == username).first()
    if user_by_name:
      errors['username'] = 'E001'
    else:
      msg = "Username is available."
  if email:
    if not util.validate_email(email):
      errors['email'] = 'E002'
      logging.info('--Invalid  EMAIL--  %s'% params['email'])
    else:
      user_by_email = session.query(model.User).filter(model.User.email == email).first()
      if user_by_email:
        errors['email'] = 'E001'
      else:
        msg = "Email is available."
  
  if errors:
    response['status'] = constants.ERROR
    response['errors'] = errors
    response['data'] = None
    return response
    
  response['status'] = constants.SUCCESS
  response['errors'] = None
  response['data'] = {'msg':msg}
  return response
  
def register_follower(follower_user, following_user_id=None):
  status = constants.SUCCESS
  followers = []
  if following_user_id:
    follower_ids = filter(lambda x:x!=str(follower_user.id), following_user_id.split(","))
    if not follower_ids:
      logging.info("Following ids are not found")
      return

    extising_users = session.query(model.User.id).filter( model.User.id.in_( follower_ids) ).all()
    extising_user_ids = [ user.id for user in extising_users ]
    if not extising_user_ids:
      logging.info("Given following_ids are not in the app.")
      return

    logging.info("extising_user_ids  = %s  "%extising_user_ids)
    already_follow_users = session.query(model.Followers).\
                                 filter(and_( 
                                    model.Followers.follower_id == follower_user.id,
                                    model.Followers.user_id.in_( extising_user_ids )
                                 ))

    followed_user_ids = [ user.user_id for user in already_follow_users]
    logging.info( "already followed user id  = %s  "% followed_user_ids)
    updatable_follower_ids = map(int, filter(lambda x: x not in followed_user_ids, extising_user_ids))
    for follower_id in updatable_follower_ids:
      followers.append({
                  'user_id':follower_id,
                  'follower_id':follower_user.id,
                  'added_date' : datetime.datetime.now(),
                  'share_count':0
                  })
    if followers:
      query = followers_table.insert().values(followers)
      session.execute(query)
      session.commit()
      util.update_followers_activity(follower_user, updatable_follower_ids)
      search_component.update_users_follower_index(follower_user, updatable_follower_ids)

      taskqueue.add(url='/tasks/update_follow_detail',
                method='POST',
                queue_name='update-follow-detail',
                params={
                        "following_ids" : ",".join(map(str, updatable_follower_ids)),
                        "follower_id" : follower_user.id,
                        "action" : constants.FOLLOW_ARTIST,
                      }
                )
  else:
    follow_by_users = util.follows_by(follower_user.email)
    logging.info('Follow By Users ::  %s' %follow_by_users)
    if follow_by_users:
      followers = []
      for user_id in follow_by_users:
        is_already_following = session.query(model.Followers).filter(model.Followers.follower_id == follower_user.id).\
                                                      filter(model.Followers.user_id == user_id).first()
        logging.info(is_already_following)                                                      
        if not is_already_following:
          followers.append({'user_id':user_id,
                            'follower_id':follower_user.id,
                            'added_date' : datetime.datetime.now(),
                            'share_count':0
                          })
      query = followers_table.insert().values(followers)
      session.execute(query)
      session.commit()
      util.update_followers_activity(follower_user, [user_id])
      search_component.update_users_follower_index(follower_user, follow_by_users)

      taskqueue.add(url='/tasks/update_follow_detail',
              method='POST',
              queue_name='update-follow-detail',
              params={
                      "following_ids" : ",".join(follow_by_users),
                      "follower_id" : follower_user.id,
                      "action" : constants.FOLLOW_ARTIST,
                    }
              )
  response = {
    'status': status,
  }

  if not status:
    response['errors'] = {"NOT_FOUND":"following user not found"}

  logging.info(response)
  return response

def un_register_follower(follower_user, following_user_id=None):
  response = {
    'status': constants.ERROR,
  }

  if following_user_id and util.get_user_by_id(following_user_id):
    follower = session.query( model.Followers ).\
                            filter( model.Followers.follower_id == follower_user.id).\
                            filter( model.Followers.user_id == following_user_id )
    if follower.all():
      for follow in follower:
        search_component.delete_follower_doc(follow.id)
      follower.delete()
      session.commit()

      follower_post_activity = session.query(model.PostActivity).\
                                  filter(model.PostActivity.user_id == int(following_user_id)).\
                                  filter(model.PostActivity.follower_id == follower_user.id).\
                                  delete()
      session.commit()

      taskqueue.add(url='/tasks/update_follow_detail',
                method='POST',
                queue_name='update-follow-detail',
                params={
                        "following_ids" : following_user_id,
                        "follower_id" : follower_user.id,
                        "action" : constants.UNFOLLOW_ARTIST,
                      }
                )
    response['status'] = constants.SUCCESS

  if not response['status']:
    response['errors'] = {"NOT_FOUND":"following user not found"}
  logging.info(response)
  return response

def get_follower_list(user, data_limit, param_offset, order_by_param=None, follower_ids=[], content_type="text"):
    
  followers_list = session.query(model.Followers, model.User).filter(model.Followers.user_id==user.id).\
                    options(
                          Load(model.Followers).load_only("id", "user_id", "follower_id", "added_date", "share_count"),
                        ).\
                    options(
                          Load(model.User).load_only("id", "username", "name", "user_type", "s3_compressed_image_key", "s3_blur_image_key", "s3_short_image_key", "s3_short_blur_image_key"),
                        ).\
                    outerjoin(model.User, and_(
                          model.User.id == model.Followers.follower_id,
                          model.User.is_active == 1,
                      )
                    ).\
                    filter(model.User.is_active == 1).\
                    group_by(model.Followers.follower_id)

  if order_by_param == constants.FRIENDSHIP_WEIGHT_ORDER:
    followers_list =  followers_list.order_by(desc(model.Followers.share_count))

  followers_list =  followers_list.order_by(desc(model.Followers.added_date)).\
                          limit( data_limit ).offset( param_offset ).all()
 
  if content_type == "json":
    followers_dict = [api_serialize.follower_to_dictionary(follower.User, follower_ids) for follower in followers_list]
  else:
    followers_dict = followers_list
  count = len(followers_dict) if followers_dict else 0
  return followers_dict, count

def get_following_list(user, data_limit, param_offset, follower_ids, content_type="text"):
  following_list = session.query(model.Followers, model.User).filter(model.Followers.follower_id==user.id).\
                            options(
                                  Load(model.Followers).load_only("id", "user_id", "follower_id"),
                                ).\
                            options(
                                  Load(model.User).load_only("id", "username", "name", "user_type", "s3_compressed_image_key", "s3_blur_image_key", "s3_short_image_key", "s3_short_blur_image_key"),
                                ).\
                            outerjoin(model.User, and_(
                                model.User.id == model.Followers.user_id,
                                model.User.is_active == 1,
                              )
                            ).\
                            filter(model.User.is_active == 1).\
                            order_by(desc(model.Followers.added_date)).\
                            limit( data_limit ).\
                            offset( param_offset )
                            
  if content_type == "json":

    following_dict = [ api_serialize.following_to_dictionary(following.User, follower_ids) for following in following_list ]

  count = len(following_dict) if following_dict else 0
  return following_dict, count

def get_settings(user, params):
    #try:
    logging.info(params)
    user_settings = {}
    genral_data = {}
    follower_ids = util.get_followers_ids(params['logged_in_user'])
    logging.info(params['user_settings'])
    logging.info(type(params['user_settings']))
    logging.info(util.is_current_user(user.id))

    if params['user_settings'] and util.is_current_user(user.id):
      user_settings = {
                   "username" : gtools.str_or_empty(user.username),
                   "name" : gtools.str_or_empty(user.name),
                   "email" : user.email,
                   "user_type":user.user_type,
                   "fb_name" : gtools.str_or_empty(user.fb_name),
                   "fb_profile_url" : gtools.str_or_empty(user.fb_profile_picture_url),
                   "twitter_name" : gtools.str_or_empty(user.twitter_name),
                   "fb_toggle" : user.fb_toggle, # TODO Need to change according to api
                   "twitter_toggle" : user.twitter_toggle, # TODO Need to change according to api
                   "playlist_toggle" : user.playlist_toggle,
                   "facebook_token" : user.facebook_token,
                   "twitter_token" : user.twitter_token,
                     }
    elif params['user_details']:
      user_settings = {
                   "username" : gtools.str_or_empty(user.username),
                   "name" : gtools.str_or_empty(user.name),

                   "user_type":user.user_type,
                   "id": user.id,
                }

      if not util.is_current_user(user.id):
        user_settings["is_following"] = util.is_following(follower_ids, user.id)
    
    user_settings["profile_image"] =  util.get_full_image_url(user, constants.USER_IMAGES_BUCKET)
    user_settings['blur_profile_image'] = util.get_full_blur_image_url(user, constants.USER_IMAGES_BUCKET)
    user_settings["blur_short_image"] =  util.get_short_blur_image_url(user, constants.USER_IMAGES_BUCKET)
    user_settings['profile_short_image'] = util.get_short_image_url(user, constants.USER_IMAGES_BUCKET)
    
    if params['follower_list_required']:
      logging.info(" ########   get the follower list ######## ")
      order_by_param = params['order_by']
      followers, follower_count = get_follower_list(user, params['limit'], params['follower_offset'], order_by_param, follower_ids, content_type="json")
      genral_data["followers"] = followers
      if len(followers) == int(params['limit']):
        genral_data["follower_offset"] = int(params['limit']) + int(params['follower_offset'])

    if params['following_list_required']:
      logging.info(" ########   get the following list ######## ")
      following, following_count = get_following_list(user, params['limit'], params['following_offset'], follower_ids, content_type="json")
      genral_data["following"] = following
      if len(following) == int(params['limit']):
        genral_data['following_offset'] = int(params['limit']) + int(params['following_offset'])

      
    if params['album_required']:
      #albums = media_component.get_album_list(user,content_required=params['content_required'], data_limit = params['limit'], album_offset = params['album_offset'], content_offset = params['content_offset'], content_type="json")
      albums = media_component.get_discography_albums(user,content_required=params['content_required'], data_limit = params['limit'], album_offset = params['album_offset'], content_offset = params['content_offset'], content_type="json")      
      if len(albums) == int(params['limit']):
        genral_data['album_offset'] = int(params['limit']) + int(params['album_offset'])
      genral_data["albums"] = albums

    if params['counts_required']:
      user_settings["following_count"] = user.following_count
      user_settings["follower_count"] = user.follower_count
      user_settings["album_count"] = media_activity_component.get_album_count(user)
      user_settings["playlist_count"] = media_activity_component.get_playlist_count(user)

    if params['artist_pages_required']:
      artist_pages = session.query(model.ArtistData).filter(model.ArtistData.user_id==user.id).\
                                               order_by(desc(model.ArtistData.added_date))
      genral_data["artist_pages"] = [api_serialize.artist_page_data_to_dictionary(artist_page) for artist_page in artist_pages]
      
    """
    if params.has_key("update_required") and params['update_required']:
      updates = media_component.get_updates(user, content_type="json")
    """

    if params.has_key("playlist_required") and params['playlist_required']:
      data_limit = params['limit'] if params['limit'] else constants.DEFAULT_QUERY_DATA_LIMIT
      genral_data["playlist"] = playlist_component.get_playlist(user,data_limit, params['playlist_offset'], remove_video_playlist=params['remove_video_playlist'])
      playlist_offset = None
      if len(genral_data["playlist"]) == int(data_limit):
        playlist_offset = int(data_limit) + int(params['playlist_offset'])
      genral_data['playlist_offset'] = playlist_offset

    """ update social params """
    social_params = {
      'facebook_token' : params["facebook_token"] if params.has_key("facebook_token") else None,
      'twitter_token' : params["twitter_token"] if params.has_key("twitter_token") else None,
    }
    
    if params['party_required']:
      data_limit = params['limit'] if params['limit'] else constants.DEFAULT_QUERY_DATA_LIMIT
      genral_data["party"] = party_component.get_party(user,data_limit, params['party_offset'])
      if len(genral_data["party"]) == int(data_limit):
        genral_data['party_offset'] = int(data_limit) + int(params['party_offset'])
    
    if params['social_friends_required']:
      social_friends, social_friend_offset = social_component.get_user_social_friends(user, params['social_friend_limit'], params['social_friend_offset'], params['order_by'])
      genral_data['social_friends'] = social_friends
      if social_friend_offset:
        genral_data['social_friend_offset'] = social_friend_offset

    response = update_social_token(user, params)

    user_settings.update(genral_data)
    response = {
                "status": True,
                "data": {
                  "user": [user_settings],
                },
                "errors": None,
            }
    return response

def update_social_token(user, social_params={}):
  if social_params['twitter_token'] or social_params['facebook_token']:
    stmt = update(model.User).where(model.User.id==user.id)
    if social_params['facebook_token']:
      stmt = stmt.values(facebook_token= social_params['facebook_token'])

    if social_params['twitter_token']:
      stmt = stmt.values(twitter_token= social_params['twitter_token'])
    result =  session.execute(stmt)
    session.commit()
    return True

  return False
  
def update_user_data(user, params):
  is_modified = False
  if params.has_key("name") and user.name != params['name']:
    user.name = params['name']
    is_modified = True

  if params['fb_name'] and user.fb_name !=params['fb_name']:
    user.fb_name = params['fb_name']
    is_modified = True

  if params['twitter_name'] and user.twitter_name !=params['twitter_name']:
    user.twitter_name = params['twitter_name']
    is_modified = True

  if params['facebook_user_permission'] and user.facebook_user_permission !=params['facebook_user_permission']:
    user.facebook_user_permission = params['facebook_user_permission']
    is_modified = True

  if params['username'] and user.username !=params['username']:
    user.username = params['username']
    is_modified = True

  if params['email'] and user.email !=params['email']:
    user.email = params['email']
    is_modified = True

  if params['password']:
    password = auth.encrypt_password(params['password'])
    if user.password != password: 
      user.password = password
      is_modified = True

  if params['fb_toggle']:
    fb_toggle = gtools.str_to_bool(params['fb_toggle'])
    if user.fb_toggle != fb_toggle: 
      user.fb_toggle = fb_toggle
      is_modified = True

  if params['twitter_toggle']:
    twitter_toggle = gtools.str_to_bool(params['twitter_toggle'])
    if user.twitter_toggle != twitter_toggle:
      user.twitter_toggle = twitter_toggle
      is_modified = True

  if params['playlist_toggle']:
    playlist_toggle = gtools.str_to_bool(params['playlist_toggle'])
    if user.playlist_toggle != playlist_toggle:
      user.playlist_toggle = playlist_toggle
      is_modified = True

  if is_modified:
    session.merge(user)
    session.commit()
  session.refresh(user)
  search_component.update_user_document(user)
  return user

def edit_settings(user, params, is_mobile=False):
  status = constants.ERROR
  try:
    if params['register_follower'] == True:
      register_follower(follower_user=user, following_user_id=params['following_id'])
    if params['register_follower'] == False:
      un_register_follower(follower_user=user, following_user_id=params['unfollowing_id'])
      
    client_errors = client_validation_editsettings(user, params, is_mobile)
    server_errors = server_validation_editsettings(user, params, is_mobile)
    response = {}
    logging.info("**"*200)
    if client_errors or server_errors:
      errors = client_errors
      errors.update(server_errors)
      response['errors'] = errors
      response['status'] = status
      response['data'] = None
    else:
      if user:
        profile_image = None
        if params['profile_image']:
          change_image_response = change_user_profile_picture(user, params['profile_image'])
          if change_image_response["status"]:
            profile_image = change_image_response["data"]["profile_image"]
          else:
            return change_image_response
        old_facebook_token = user.facebook_token
        user = update_user_data(user, params)

        if params.has_key("twitter_token") and params['twitter_token'] and params.has_key("twitter_secret") and params['twitter_secret'] and params.has_key("twitter_id"):
          social_component.update_twitter_detail(user, params)

        if session.is_modified(user, passive=True):
          user.modified_date = datetime.datetime.now()
          session.merge(user)
          session.commit()
          search_component.update_user_document(user)

        playlist_id = None
        party_id = None
        if params.has_key("password") and params['password']:
          gaesessions.freez_all_other_sessions_by_user()
        if params['party_name']:
          party_response = party_component.create_party(user, params)
        if params['playlist_name']:
          playlist_id = playlist_component.create_playlist(params['playlist_name'], user)
          if params['content_ids']:
            playlist = util.get_playlist_by_id(playlist_id)
            res = playlist_component.add_content_on_playlist(params['content_ids'], playlist)
            if res:
              taskqueue.add(url='/tasks/update_library_contents',
                  method='POST',
                  queue_name='update-library-contents',
                  params={
                          "user_ids" : str(user.id),
                          "playlist_id" : playlist.id,
                          "content_ids" : params['content_ids'],
                        }
                  )

        session.commit()
        if params.has_key("facebook_token") and params['facebook_token'] and params['facebook_token'] != str(old_facebook_token):
          logging.info(old_facebook_token)
          logging.info(params['facebook_token'])
          social_component.update_facebook_detail(user, params['facebook_token'], user_permission = params['facebook_user_permission'])

        data = {
            'user': [{
                  'user_id' : user.id,
                  'username' : user.username,
                  'playlist_id' : playlist_id,
                  'user_type': user.user_type
            }],
        }
        if profile_image: data['user'][0]['profile_image'] = profile_image
        if params['party_name']:
          data['user'][0].update(party_response)
        status = constants.SUCCESS
        response['status'] = status
        response['data'] = data
        response['errors'] = None
        
  except Exception as e :
    logging.exception(e)
    response =  {
                 "status": status,
                 "data": None,
                 "errors": {"error":"Database fetch operation failed."}       
               }  
  
  logging.info("edit settings response ::  %s"%response)
  return response
  
def fans_list(user):
  fan_list = session.query(model.FanList).filter(model.FanList.user_id == user.id)
  return fan_list

def is_liked_by_logged_in_user(user, post):
  pass

def get_post_object(user, current_user):
  events = [constants.EVENT_FOR_CREATE_PARTY, 
            constants.EVENT_FOR_PLAYLIST_CREATE]

  content_events = [constants.EVENT_FOR_CONTENT_UPLOAD,
                    constants.EVENT_FOR_CONTENT_SHARE,
                    constants.EVENT_FOR_POST_TO_FEED]

  event_for_self = [constants.EVENT_FOR_CREATE_PARTY,
                    constants.EVENT_FOR_POST_TO_FEED]

  follower_list = session.query(model.Followers).filter(model.Followers.follower_id == user.id)
  follower_user_ids = [follower_user.user_id for follower_user in follower_list]
  logging.info(follower_user_ids)
  posts = session.query(model.Post,
                          model.PostActivity.id.label("post_activity_id"),
                          model.PostActivity.added_date.label("post_activity_modified_date"),
                          model.User,
                          model.Content,
                          ).\
                          options(
                            Load(model.Content).load_only("id"),
                          ).\
                          options(
                            Load(model.User).load_only("id"),
                          ).\
                          outerjoin(model.Content, and_(model.Content.id == model.Post.content_id ) ).\
                          outerjoin(model.User, and_( model.User.id == model.Post.user_id, model.User.is_active == 1) ).\
                          outerjoin(model.PostActivity, 
                                and_(
                                    model.PostActivity.post_id == model.Post.id,
                                    model.PostActivity.user_id == current_user.id,
                                    model.PostActivity.activity_type == constants.ACTIVITY_LIKE 
                                )
                          ).\
                          filter(
                            or_(
                                  and_(
                                        or_(and_(model.Post.event_type==constants.EVENT_FOR_CONTENT_SHARE,
                                                model.Post.user_id == user.id, 
                                            ),
                                            and_(
                                                model.Post.shared_user_id == user.id, 
                                                model.Post.event_type ==constants.EVENT_FOR_PLAYLIST_SHARE
                                              )
                                        ) 
                                  ),
                                  and_(
                                        model.Post.user_id == user.id ,
                                        model.Post.event_type == constants.EVENT_FOR_CREATE_PARTY,
                                        model.User.is_active == 1,
                                  ),
                                  and_(
                                        model.Post.user_id == user.id ,
                                        model.Post.event_type == constants.EVENT_FOR_POST_TO_FEED,
                                  ),
                                  and_(
                                        model.Post.user_id.in_(follower_user_ids),
                                        model.Post.event_type.in_(content_events),
                                  ),
                                  and_(
                                        model.Post.user_id.in_(follower_user_ids),
                                        model.Post.event_type.in_(events),
                                        model.User.is_active == 1,
                                  )
                            )
                          )
  return posts

def get_real_time_feeds(user, limit, next_datetime, prev_datetime, current_user = None, cache_modified=False):
  follower_ids = util.get_followers_ids(user)
  if not current_user:
    current_user = user

  posts = get_post_object(user, current_user)

  #check for don't show old post
  if cache_modified:
    order_by = "desc"
    if next_datetime:
      posts = posts.filter(model.Post.modified_date < next_datetime)

    if prev_datetime:
      order_by = "asc"
      posts = posts.filter(model.Post.modified_date > prev_datetime)

    posts = posts.filter(model.Post.modified_date != model.Post.added_date).group_by(model.Post.id)
    if order_by == "asc":
      posts = posts.order_by(model.Post.modified_date)
    else:
      posts = posts.order_by(desc(model.Post.modified_date))

    logging.info("========Post ids=============")
    logging.info(user.modified_date)
  else:
    order_by = "desc"
    posts = posts.filter(model.Post.is_deleted == 0)
    if next_datetime:
      posts = posts.filter(model.Post.added_date < next_datetime)

    if prev_datetime:
      order_by = "asc"
      posts = posts.filter(model.Post.added_date > prev_datetime)

    posts = posts.group_by(model.Post.id)
    if order_by == "asc":
      posts = posts.order_by(model.Post.added_date)
    else:
      posts = posts.order_by(desc(model.Post.added_date))

    posts = posts.limit(limit).all()

    logging.info("========Post ids=============")
    logging.info(user.added_date)

  sorted_by = "modified_date" if cache_modified else "added_date"

  like_data = {}
  post_ids = []

  for post in posts:
    post_ids.append(post.Post.id)
    like_data[post.Post.id] = post.post_activity_id

  notifications, ds_users = ds_post_component.get_feed_data(post_ids, like_data, current_user, follower_ids=follower_ids, like_required=False)
  #notifications = party_component.convert_post_obj_to_json(posts, user)
  #comments_on_post = get_follower_comments_on_post(user, follower_user_ids, limit, next_datetime, prev_datetime)
  #notifications.extend( comments_on_post )
  for er in notifications:
    logging.info("date %s post_id %s"%(er['added_date'],er['post_id']))
  sorted_notifications = sorted(notifications, key=operator.itemgetter(sorted_by), reverse= True if order_by == "desc" else False )[:limit]
  sorted_notifications = sorted(sorted_notifications, key=operator.itemgetter(sorted_by), reverse= True)
  sorted_notifications = ds_content_component.add_is_like_in_content_object(user, sorted_notifications)
  response = {
	  "status" : constants.SUCCESS,
	  "data" : {
        "notifications" : sorted_notifications,
       },
    "errors" : None,
  }

  return response

def get_real_time_feeds_count(user, limit, next_datetime, prev_datetime, current_user = None):
  if not current_user:
    current_user = user

  posts = get_post_object(user, current_user)
  posts = posts.filter(model.Post.is_deleted == 0)
  #check for don't show old post
  order_by = "desc"
  if next_datetime:
    posts = posts.filter(model.Post.added_date < next_datetime)

  if prev_datetime:
    order_by = "asc"
    posts = posts.filter(model.Post.added_date > prev_datetime)

  posts = posts.group_by(model.Post.id)
  if order_by == "asc":
    posts = posts.order_by(model.Post.added_date)
  else:
    posts = posts.order_by(desc(model.Post.added_date))

  posts = posts.limit(limit).all()
  
  total_count = len(posts)
  #comments_on_post = get_follower_comments_on_post(user, follower_user_ids, limit, next_datetime, prev_datetime)
  #total_count += len(comments_on_post)
  response = {
	  "status" : constants.SUCCESS,
	  "data" : {
        "notifications_count" : total_count,
       },
    "errors" : None,
  }

  return response


def play_feed_songs(user, post_id, timestamp=None, playlist_id=None, limit=constants.DEFAULT_QUERY_DATA_LIMIT, playlist_offset=constants.DEFAULT_FEED_PLAYLIST_CONTENT_OFFSET):

  response =  {
    "status" : constants.SUCCESS,
    "data" : None,
    "errors" : None,
  }

  notifications = []
  if playlist_id:
    playlist_content = session.query(model.PlaylistContent,model.Content).\
                            options(
                              Load(model.Content).load_only("id", "title", "duration", "play_count", "content_type", "genre_id", "album_id", "user_id", "format", "s3_Key","video_frame", "is_converted", "short_video_frame", "video_frame_height", "video_frame_width", "s3_Key_before_convert", "has_lyrics"),
                            ).\
                            options(
                              joinedload(model.Content.user).load_only("id", "username", "name", "user_type", "s3_compressed_image_key", "s3_blur_image_key", "s3_short_image_key", "s3_short_blur_image_key"),
                            ).\
                            options(
                              joinedload(model.Content.album).load_only("id", "album_name", "s3_compressed_image_key", "s3_blur_image_key", "s3_short_image_key", "s3_short_blur_image_key"),
                            ).\
                            join(model.Content, and_(model.Content.id == model.PlaylistContent.content_id, model.Content.is_hidden == 0 )).\
                            filter( model.PlaylistContent.playlist_id == playlist_id).\
                            order_by(model.PlaylistContent.id).\
                            limit(limit).offset(playlist_offset).all()

    if playlist_content:
      content_ids = [int(content.Content.id) for content in playlist_content]
      liked_contents = util.get_content_likes(user, content_ids)
      for content in playlist_content:
        data = {
          'post_id' : post_id,
          'playlist' : [{"id" : playlist_id}],
          "added_date" : gtools.dt_to_timestamp(timestamp),
          "content" : [api_serialize.content_to_dictionary(content.Content, video_frame_url=content.Content.video_frame, liked_contents=liked_contents)]
        }
        notifications.append(data)

    logging.info(notifications)
    logging.info(limit)
    if len(notifications) == int(limit):
      response["data"] = {
            "notifications" : notifications,
            "offset" : int(limit) + int(playlist_offset),
      }
      return response


  limit -= len(notifications)
  logging.info(limit)

  follower_list = session.query(model.Followers).filter(model.Followers.follower_id == user.id).all()
  follower_user_ids = [follower_user.user_id for follower_user in follower_list]
  logging.info(follower_user_ids)
  posts = session.query(model.Post, model.Content).\
                          options(
                              Load(model.Post).load_only("id", "added_date", "content_id"),
                          ).\
                          options(
                              Load(model.Content).load_only("id", "title", "duration", "play_count", "content_type", "genre_id", "album_id", "user_id", "format", "s3_Key","video_frame", "is_converted", "short_video_frame", "video_frame_height", "video_frame_width", "s3_Key_before_convert", "has_lyrics"),
                          ).\
                          options(
                            joinedload(model.Content.user).load_only("id", "username", "name", "user_type", "s3_compressed_image_key", "s3_blur_image_key", "s3_short_image_key", "s3_short_blur_image_key"),
                          ).\
                          options(
                              joinedload(model.Content.album).load_only("id", "album_name", "s3_compressed_image_key", "s3_blur_image_key", "s3_short_image_key", "s3_short_blur_image_key"),
                          ).\
                          join(model.Content, and_(model.Content.id == model.Post.content_id ) ).\
                          filter(or_(
                              and_(
                                model.Post.event_type.in_([constants.EVENT_FOR_CONTENT_SHARE, constants.EVENT_FOR_POST_TO_FEED]),
                                model.Post.user_id == user.id,
                              ),
                              and_(
                                model.Post.user_id.in_(follower_user_ids),
                                model.Post.event_type.in_([constants.EVENT_FOR_CONTENT_UPLOAD, constants.EVENT_FOR_CONTENT_SHARE, constants.EVENT_FOR_POST_TO_FEED]),
                              ),
                            )
                          ).\
                          filter(and_(model.Content.is_hidden==0, model.Content.content_type==2))

  '''
                          filter(or_(
                                  and_( model.Followers.follower_id == user.id,
                                       model.Post.event_type.in_([constants.EVENT_FOR_CONTENT_UPLOAD, constants.EVENT_FOR_POST_TO_FEED]) ),
                                  and_( model.Post.event_type == constants.EVENT_FOR_CONTENT_SHARE,
                                      model.Post.shared_user_id == user.id)
                                )).\
  '''
                          
  if timestamp:
    posts = posts.filter(model.Post.added_date < timestamp )

  posts = posts.group_by(model.Post.id).order_by(desc(model.Post.added_date)).\
                    limit(limit).all()

  content_ids = [int(post.Content.id) for post in posts]
  liked_contents = util.get_content_likes(user, content_ids)

  for post in posts:
    data = {'post_id' : post.Post.id,
            'added_date' : gtools.dt_to_timestamp(post.Post.added_date),
            'content' : [api_serialize.content_to_dictionary(post.Content, liked_contents=liked_contents)],
      }
    notifications.append(data)

  response["data"] = { "notifications" : notifications }
  return response

def change_user_profile_pic(user_id, profile_image, is_mobile=False):
  data, errors = None, None
  response = {
    'status': constants.ERROR,
    'data' : None,
    'errors' : None,
  }

  file_name = None
  if not is_mobile:
    img = profile_image.replace("data:image/png;base64,", "")
    file_name = 'real_user_image' + util.get_unique_key() + ".jpg"
    gcs_blob_key = gtools.write_gcs_blob(base64.decodestring(img), file_name)
    image_url = gap_image.get_serving_url(str(gcs_blob_key)) + str("=s0")
    profile_image = db.Blob(urlfetch.Fetch(image_url).content)

  if profile_image:
    errors = util.check_valid_image(profile_image)
    if errors:
      response["errors"] = errors
      return response

  user = util.get_user_by_id(user_id, load_only_params=True)
  old_s3_key = user.s3_image_key
  old_s3_rescale_image_key = user.s3_rescale_image_key
  old_compressed_image_key = user.s3_compressed_image_key
  old_short_image_key = user.s3_short_image_key

  img_format = constants.IMAGE_FORMATS[gap_image.Image(profile_image).format].lower()
  logging.info(img_format)
  # uploading the origional image on s3
  s3_key = user.username+"_"+str(util.get_unique_key()) +"_"+ str(user.id) +"." + img_format
  s3_key = s3_key.replace(" ","")
  image_key = boto_lib.save_img_in_s3(profile_image, s3_key, constants.USER_IMAGES_BUCKET)

  # uploading the rescale image on s3
  rescale_image = util.rescale(profile_image, width=141, height=141)
  rescale_image_s3_key = user.username+"_rescale_"+str(util.get_unique_key()) +"_"+ str(user.id) +"." + img_format
  rescale_image_s3_key = rescale_image_s3_key.replace(" ","")
  rescale_image_s3_key = boto_lib.save_img_in_s3(rescale_image, rescale_image_s3_key, s3_bucket=constants.USER_IMAGES_BUCKET)

  user.s3_image_key = image_key
  user.s3_rescale_image_key = rescale_image_s3_key
  user.s3_compressed_image_key = None
  user.s3_short_image_key = None
  session.commit()

  if file_name and gcs_blob_key:
    logging.info("deleting blob_key :: %s"%str(gcs_blob_key))
    gtools.delete_gcs_blob(file_name)

  logging.info(old_s3_key)
  delete_keys = []
  if not old_s3_key in constants.USER_DEFAULT_IMAGES:
    logging.info("Deleting old images for user %s ."%user.username)
    delete_keys.append(old_s3_key)
    delete_keys.append(old_s3_rescale_image_key)

  if old_short_image_key:
    if not "short_default_user_image_" in old_short_image_key:
      delete_keys.append(old_short_image_key)

  if old_compressed_image_key:
    if not "compressed_default_user_image_" in old_compressed_image_key:
      delete_keys.append(old_compressed_image_key)

  taskqueue.add(url='/tasks/delete_s3_data',
              method='POST',
              queue_name='blur-album-image',
              params={ 'data_type' : 'User',
                  's3_keys': ",".join(delete_keys)}
              )

  send_request_to_update_compressed_user_image(user)
  response["status"] = constants.SUCCESS
  response['data'] = {"profile_image": boto_lib.get_image_url(s3_bucket=constants.USER_IMAGES_BUCKET, s3_key=image_key)} if is_mobile else {"image_url": boto_lib.get_image_url(s3_bucket=constants.USER_IMAGES_BUCKET, s3_key=rescale_image_s3_key)}
  return response

def twitter_user_settings(user, params):
  response = {
      "status" : constants.ERROR,
      "data" : None,
      "errors" : None
  }
  try:
    if params['key'] and params['secret']:    
      key, secret = oauthclient.exchange_request_token_for_access_token(constants.TWITTER_CONSUMER_KEY,
                                                                        constants.TWITTER_CONSUMER_SECRET,
                                                                        constants.TWITTER_ACCESS_TOKEN_URL,
                                                                        params['verifier'],
                                                                        params['key'],
                                                                        params['secret'])

      twitapi = twitter.Api(constants.TWITTER_CONSUMER_KEY,
                            constants.TWITTER_CONSUMER_SECRET,
                            key,
                            secret,
                            cache=None)
      twituser = twitapi.VerifyCredentials()
      logging.info(twituser)
      user.twitter_token = key
      user.twitter_secret = secret
      user.twitter_id = twituser.id
      user.twitter_name = twituser.screen_name
      user.is_updated_twitter_friends = True
      session.merge(user)
      session.commit()
      taskqueue.add(url='/tasks/notification_for_joined_user',
        method='GET',
        queue_name='update-library-contents',
        params={
              "user_id" : str(user.id),
              "activity": constants.TWITTER_JOIN
            }
      )
      social_component.update_social_network(user, constants.TWITTER_USER)
      social_component.follow_veromuse_on_twitter(user)
      response['status'] =  constants.SUCCESS
      response['data'] = {'msg':'settings Saved Successfully.'}
    else:
      response['errors'] =  {"error":"Invalid Key and Secret."}
  except Exception as e:
    logging.exception(e)
    response['errors'] =  {"error":"Faild to Fetch Data from database."}
  return response
  
def get_gallery_album(user, offset, limit):
  gallery_albums = session.query(model.GalleryAlbum).order_by(desc(model.GalleryAlbum.added_date)).\
                                      limit(limit).offset(offset)
  album_list = []
  for gallery_album in gallery_albums:
    data_dict = {
      "id" : gallery_album.album.id,
      "name" : gtools.str_or_empty(gallery_album.album.album_name),
      "content_count" : len(gallery_album.album.contents),
    }
    if gallery_album.album.images and gallery_album.album.images.full_file_loc:
      data_dict["album_image"] = util.get_album_image_url(gallery_album.album.images.full_file_loc)
    else:
      data_dict["album_image"] = None
    
    data_dict['vote'] = 0
    for album_vote in gallery_album.album_vote:
      if album_vote.user_id == user.id and album_vote.gallery_album_id == gallery_album.id:
        data_dict['vote'] = album_vote.vote_type
    album_list.append(data_dict)
      
  response = {
     "status": constants.SUCCESS,
     "data": {
            "albums" : album_list,
     },
     "errors": None
	 }

  if len(album_list) == int(limit):
    response['data']['offset'] = int(limit) + offset

  return response 
  
def edit_gallery_album(user, params):
  response = {
      'status' : constants.ERROR,
      'data' :None,
      'errors':None
  }

  errors_response = gallery_validation(user, params)
  logging.info("error response :: %s"%errors_response)
  if errors_response:
    response['errors'] = errors_response
    return response
  
  album_vote = session.query(model.GalleryAlbumVote).filter(model.GalleryAlbumVote.album_id == params['album_id']).\
                                                          filter(model.GalleryAlbumVote.user_id == user.id)
  album_vote_obj =  album_vote.first()                                                         
  if album_vote_obj:
    if params['vote'] == 1:
      response['errors'] = {"error": "The Album is already up-voted."}
    else: # remove vote.
      gallery_album = session.query(model.GalleryAlbum).filter(model.GalleryAlbum.id == album_vote_obj.gallery_album_id).\
                                                          filter(model.GalleryAlbum.album_id == params['album_id']).first()
      gallery_album.vote_count = gallery_album.vote_count-1
      session.merge(gallery_album)
      session.commit()                                                     
      album_vote.delete()
      session.commit()
      response['data'] = {'album_id': params['album_id']}
      response['status'] = constants.SUCCESS
  else:
    if params['vote'] == 0:
      response['errors'] = {"error": "The Album is not voted yet."}
    else:   # add vote.
      gallery_album = session.query(model.GalleryAlbum).filter(model.GalleryAlbum.album_id == params['album_id']).first()
      if not gallery_album:
        gallery_album = model.GalleryAlbum()
        gallery_album.album_id = params['album_id']
        session.add(gallery_album)
        session.flush()
        session.commit()
      
      album_vote = model.GalleryAlbumVote()
      album_vote.album_id = params['album_id']
      album_vote.vote_type = params['vote']
      album_vote.gallery_album_id = gallery_album.id
      album_vote.user_id = user.id
      session.add(album_vote)
      session.flush()
      session.commit()
      
      gallery_album.vote_count = gallery_album.vote_count+1
      session.merge(gallery_album)
      session.commit()
      media_activity_component.update_real_time_feeds(
                              gallery_vote_id = album_vote.id,
                              user_id = user.id,
                              event_type = constants.EVENT_FOR_GALLERY_VOTE,
                              event_for = constants.EVENT_FOR_GALLERY,
                            )
        
      response['data'] = {'album_id': params['album_id']}
      response['status'] = constants.SUCCESS
  return response

def slash_vote_count():
  gallary_albums = update(model.GalleryAlbum).\
      values(vote_count = (model.GalleryAlbum.vote_count/2))
  result =  session.execute(gallary_albums)
  session.flush()
  session.commit()
  return

def update_twiter_friends(user):
  task_params = {
    'user_id': user.id,
    'social_network_type': user.id,
  }
  taskqueue.add(url='/tasks/stop_current_streaming',
                method='GET',
                queue_name='stop-streaming',
                params=task_params)

def gallery_validation(user, params):
  errors = {}
  if params['vote'] == None:
    logging.info("missing vote value.")
    errors['vote'] = constants.PARAM_REQUIRED
  else:
    if not (int(params['vote']) == 1 or int(params['vote']) == 0):
      logging.info("invalid vote value.")
      errors['vote'] = constants.INVALID_VALUE
  album = session.query(model.Album).filter(model.Album.id == params['album_id']).first()
  if not album:
    errors['album_id'] = constants.INVALID_VALUE

  return errors
  
def send_request_for_user_blur_image(user_id, s3_image_key=None):
  user = util.get_user_by_id(user_id)
  logging.info(user.s3_image_key)

  s3_image_key = user.s3_compressed_image_key if user.s3_compressed_image_key else s3_image_key
  if s3_image_key:
    user_image_url = boto_lib.get_image_url(constants.USER_IMAGES_BUCKET, s3_image_key)
    urlfetch.set_default_fetch_deadline(100)
    url = constants.EC2_SERVER_URL_FOR_BLUR_IMAGE + "/blur_user_image?user_id=%s&user_image_url=%s&env=%s"%( user.id, user_image_url, str(gtools.get_env()))
    logging.info(url)
    response = urlfetch.fetch(url)
    logging.info(response)
  return True

def add_user_blur_image(user_id, blur_image):
  user = util.get_user_by_id(user_id)
  logging.info(user)
  if blur_image and user:
    old_blur_image = user.s3_blur_image_key
    old_short_image = user.s3_short_blur_image_key

    short_image = util.rescale_image(blur_image, max_width=90)

    s3_key = save_user_image_on_s3(blur_image, user, s3_bucket=constants.USER_IMAGES_BUCKET, s3_key=None)

    short_image_s3_key = gtools.ignore_special_charecter(user.username)+"_short_blured_"+str(util.get_unique_key()) +"_"+ str(user.id) +".jpeg"
    short_image_s3_key = short_image_s3_key.replace(" ","")
    short_image_s3_key = boto_lib.save_img_in_s3(short_image, short_image_s3_key, s3_bucket=constants.USER_IMAGES_BUCKET)

    logging.info(s3_key)
    logging.info(short_image_s3_key)

    user.s3_blur_image_key = s3_key
    user.s3_short_blur_image_key = short_image_s3_key
    session.merge(user)
    session.flush()
    session.commit()

    if old_blur_image:
      boto_lib.delete_image_from_s3(constants.USER_IMAGES_BUCKET, old_blur_image)
    if old_short_image:
      boto_lib.delete_image_from_s3(constants.USER_IMAGES_BUCKET, old_short_image)

    response = {
      'status': constants.SUCCESS,
      'data': {
        'msg' : "user %s blur image update successfully."%user.username
       },
    }
  else:
    response = {
      'errors':{"msg" : "user not found"},
      'status': constants.ERROR,
      'data': None
    }
  return response
  
def create_task_quque_for_bunch_of_users(limit, offset):
  logging.info("limit ::   %s"%limit)
  logging.info("offset ::   %s"%offset)
  users = session.query(model.User).\
                      filter(model.User.blur_image_id == None).\
                      order_by(model.User.id).\
                      limit(limit).offset(offset)
  logging.info([user.id for user in users])                      
  for user in users:
    if user.image_id and user.images:
      logging.info("create_task queue for user id =%s "%user.id)
      taskqueue.add(url='/tasks/blur_user_image',
                  method='GET',
                  queue_name='blur-user-image',
                  params={ 'user_id': user.id}
                  )

def send_notification_to_user(notification_params):
  logging.info(notification_params)
  if notification_params["action"] == constants.DELETE_PARTY_USER and notification_params['party_id']:
    party = party_component.get_party_by_id(notification_params['party_id'])
    if party and notification_params["activitiy_user_ids"]:
      deleted_user_ids = [ int(x) for x in notification_params["activitiy_user_ids"].split(",") ]
      sub_host_user_ids = party_component.get_sub_host_users( party.id )
      sub_host_user_ids.append(party.user_id) # add host user in notification user's list
      sub_host_user_ids.extend( deleted_user_ids ) # add all deleted user's ids
      for sub_host_user_id in sub_host_user_ids:
        notifi_params = {}
        notifi_params['activity'] = notification_params["action"]
        notifi_params['party_id'] = party.id
        if sub_host_user_id in deleted_user_ids:
          notifi_params['is_delete'] = True

        util.send_notification_to_device([sub_host_user_id], party.user_id, notifi_params)

  if notification_params["action"] == constants.PARTY_JOIN and notification_params['party_id']:
    party = party_component.get_party_by_id(notification_params['party_id'])
    if party:
      sub_host_user_ids = party_component.get_sub_host_users( party.id )
      sub_host_user_ids.append(party.user_id) # add host user in notification user's list
      if sub_host_user_ids:
        party_component.send_notification_for_party_updates(party_id=party.id,
                                                          sender_id=party.user_id,
                                                          receiver_user_ids=sub_host_user_ids, 
                                                          activitiy=notification_params["action"],
                                                          message=notification_params["message"] )



  if notification_params["action"] in [constants.CONTENT_ADD_IN_PARTY,constants.DELETE_PARTY_CONTENT, constants.PLAY_PARTY_CONTENT] and notification_params['party_id']:
    party = party_component.get_party_by_id(notification_params['party_id'])
    if party:
      party_user_ids = party_component.get_party_users(party.id)
      if party_user_ids:
        party_component.send_notification_for_party_updates(party_id=party.id,
                                                          sender_id=party.user_id,
                                                          receiver_user_ids=party_user_ids,
                                                          activitiy=notification_params["action"],
                                                          message=notification_params["message"] )

  if notification_params["action"] == constants.DELETING_PARTY and notification_params['party_id']:
    party = party_component.get_party_by_id(notification_params['party_id'])
    if party:
      party_user_ids = party_component.get_sub_host_and_guest_users(party.id)
      notifi_params = {}
      notifi_params['activity'] = notification_params["action"]
      notifi_params['party_id'] = party.id
      notifi_params['party_name'] = party.name
      util.send_notification_to_device(party_user_ids, party.user_id, notifi_params)



  if notification_params["action"] == constants.ADD_SUBHOST and notification_params['party_id']:
    party = party_component.get_party_by_id(notification_params['party_id'])
    if party:
      user_ids = notification_params["activitiy_user_ids"].split(",")
      user_ids = [ int(user_id) for user_id in user_ids ]
      party_component.send_notification_for_party_updates(party_id=party.id,
                                                        sender_id=party.user_id,
                                                        receiver_user_ids=user_ids,
                                                        activitiy=notification_params["action"],
                                                        message=notification_params["message"] )

  if notification_params["action"] == constants.PARTY_ENDED and notification_params['party_id']:
    party = party_component.get_party_by_id(notification_params['party_id'])
    if party:
      party_user_ids = party_component.get_party_users(party.id)
      party_component.send_notification_for_party_updates(party_id=party.id,
                                                        sender_id=party.user_id,
                                                        receiver_user_ids=party_user_ids,
                                                        activitiy=notification_params["action"] )


def set_user_image():
  users = session.query(model.User).filter(
                                        or_(
                                            model.User.image_id == None,
                                            model.User.blur_image_id == None
                                            )
                                   ).\
                                   order_by(model.User.id).limit(10).all()
  totel_user = len(users)
  user_ids = []
  for user in users:
    user_ids.append(user.id)
    util.save_profile_image(user)
    taskqueue.add(url='/tasks/blur_user_image',
                    method='GET',
                    queue_name='blur-user-image',
                    params={ 'user_id': user.id}
                    )
  data = {
            'user_ids' : user_ids,
            'totel_user': totel_user
  }
  
  response = {
      'status' : constants.SUCCESS,
      'data' : data,
      'errors' : None
  }
  
  return response

def get_follower_comments_on_post(user, follower_list, limit, next_datetime, prev_datetime):

  comments_on_post = session.query(model.PostActivity ).\
                         join(model.Content, and_( model.Content.id == model.PostActivity.content_id,
                                                    model.Content.is_hidden ==0 ) ).\
                          filter(model.PostActivity.activity_type == constants.ACTIVITY_COMMENT ).\
                          filter(model.PostActivity.user_id.in_(follower_list))

  order_by = "desc"
  if next_datetime:
    comments_on_post = comments_on_post.filter( model.PostActivity.added_date < next_datetime)

  if prev_datetime:
    order_by = "asc"
    comments_on_post = comments_on_post.filter( model.PostActivity.added_date > prev_datetime)

  if order_by == "desc":
    comments_on_post = comments_on_post.order_by(desc(model.PostActivity.added_date)).\
                                     limit(limit).all()
  else:
    comments_on_post = comments_on_post.order_by(model.PostActivity.added_date).\
                                     limit(limit).all()

    
  notifications = []
  post_ids = []
  user_ids = []
  for post_activity in comments_on_post:
    user_ids.append(post_activity.post_user_id)
    user_ids.append(post_activity.user_id)
    post_ids.append(post_activity.post_id)
  logging.info(user_ids)
  posts = ds_post_component.get_ds_posts_dict(post_ids)
  for key, post in posts.items(): 
    user_ids.append(post.content.user)

  #users = ds_user_component.get_ds_users_serialise(user_ids)
  users = ds_user_component.get_ds_users_dict(user_ids)
  
  content_ids = []
  for activity in comments_on_post:
    post = posts[str(activity.post_id)]
    content_ids.append(int(post.content.id_))
  liked_contents = util.get_content_likes(user, content_ids)

  for post_activity in comments_on_post:
    post = posts[str(post_activity.post_id)]
    notification_data = {
      "post_activity_id" : post_activity.id,
      "activity_type" : "post_comment",
      "shared_user" : [users[str(post_activity.post_user_id)]],
      "post_user" : [users[str(post_activity.user_id)]],
      "comment" : post_activity.comment,
      "added_date" : gtools.dt_to_timestamp(post_activity.added_date),
      "modified_date" : gtools.dt_to_timestamp(post_activity.added_date),
      "content" : [api_serialize.ds_content_to_dictionary(post.content, liked_contents=liked_contents)],
      "post_id" : post.id_
    }
  
    notification_data['content'][0]['user'] = [users[notification_data['content'][0]['user']]]
    
    notification_data["is_liked"] = True if post_activity.id else False
    notifications.append(notification_data)

  return notifications

def save_support_log(user, params):
  response = {
      'data':None,
      'errors': None,
      'status' : constants.ERROR
  }
  try:
    errors = save_support_log_validation(user, params)   
    if errors:
      response['errors'] = errors
      return response

    file_name = 'support_log_file' + util.get_unique_key() + '_log'
    gcs_blob_key = gtools.write_gcs_blob(params['file_content'], file_name, mime_type='application/octet-stream')
    if gcs_blob_key:
      mobIssueObj = model.SupportIssue()
      mobIssueObj.user_id = user.id
      mobIssueObj.title = params['subject']
      mobIssueObj.description = params['description']
      mobIssueObj.logfile_key = str(gcs_blob_key)
      if params['image']:
        mobIssueObj.s3_image_key = save_supportlog_image_on_s3(params['image'], user, s3_bucket=constants.SUPPORT_LOG_IMAGE_BUCKET)
      mobIssueObj.logfile_name = params['file_name']
      mobIssueObj.added_date = datetime.datetime.now()
      session.add(mobIssueObj)
      session.flush()
      session.commit()

      task_params = {
            "to" : params['to'],
            "sender" : user.email,
            "subject" : params['subject'],
            "log_file_id" : mobIssueObj.id,
            "description": params['description'],
            "username" : user.username
      }

      taskqueue.add(url='/tasks/email_support_log',
                queue_name='email',
                params=task_params)
      response['data'] = {'msg': "Thank you for submitting your report, we will get back to you asap!"}
      response['status'] = constants.SUCCESS
    else:
      response['errors'] = {'log_file' : constants.INVALID_VALUE}
  except Exception as e :
    logging.exception(e)
    response['errors'] = {'error': 'Failed to fetch data from database.'}
  return response

def save_support_log_validation(user, params):
  errors = {}
  if not params['file_name']:
    errors['log_file'] = constants.PARAM_REQUIRED
  if not params['to']:
    errors['to'] = constants.PARAM_REQUIRED
  return errors 


def get_conversation_for_thread_count(user, thread_id):
  response = {
      'status' : constants.ERROR,
      'data' : None,
      'errors' : None
  }
  try :
    user_thread = get_user_thread_by_id(thread_id)
    if not user_thread:
      response['errors'] = {"thread_id" : constants.INVALID_VALUE}
      return response

    conversation = session.query(model.ConversationThread).\
                            join(model.UserThread, model.ConversationThread.thread_id == model.UserThread.id).\
                            filter( model.UserThread.id == thread_id).all()

    response["data"] = {
                  "conversation_count" : len(conversation),
                  "thread_id" : int(thread_id)
            }
    response["status"] = constants.SUCCESS
  except Exception as e:
    logging.exception(e)
    response['errors'] =  {"error":"Failed to fetch data from database."}  
  return response

def get_conversation_for_thread(user, thread_id, limit=None, offset=None):
  user_thread = get_user_thread_by_id(thread_id)
  follower_ids = util.get_followers_ids(user)
  if not user_thread:
    response = {
        'status' : constants.ERROR,
        'data' : None,
        'errors' : {"thread_id" : constants.INVALID_VALUE,
                  "error" : constants.INVALID_VALUE 
                  }
    }
    return response  


  conversation = session.query(model.ConversationThread).\
                          join(model.UserThread, model.ConversationThread.thread_id == model.UserThread.id).\
                          filter( model.UserThread.id == thread_id).\
                          order_by(desc(model.ConversationThread.sent_datetime)).\
                          limit(limit).\
                          offset(offset)

  conversation_thread = {'user_1': [api_serialize.user_to_dictionary(user_thread.user_1) ],
                         'user_2' : [api_serialize.user_to_dictionary(user_thread.user_2)], 
                        }
  convs = []

  post_activitie_ids = [int(conv.post_activity_id) for conv in conversation if conv.post_activity_id]
  conversation_dict = get_user_private_message(user, post_activitie_ids, follower_ids=follower_ids)
  logging.info(conversation_dict)
  for conv in conversation:
    conversation_obj = api_serialize.conversation_to_dictionary(conv)
    if conv.post_activity_id and conversation_dict.has_key(int(conv.post_activity_id)):
      conversation_obj["private_message"] = [conversation_dict[int(conv.post_activity_id)]]
    convs.append( conversation_obj )

  sorted_convs = sorted(convs, key=operator.itemgetter('sent_datetime'), reverse=False)
  conversation_thread['conversation'] = sorted_convs

  is_modified = False

  user_1_new_message = user_thread.user_1_new_message
  user_2_new_message = user_thread.user_2_new_message

  if user.id == user_thread.user_1_id:
    if bool(user_1_new_message) != False:
      user_1_new_message = False
      is_modified = True
  else:
    if bool(user_2_new_message) != False:
      user_2_new_message = False
      is_modified = True

  logging.info("----  is_modified  %s"%str(is_modified))

  if is_modified:
    update_user_thread = update(model.UserThread).\
                      where(model.UserThread.id ==thread_id ).\
                      values(user_1_new_message = user_1_new_message, user_2_new_message=user_2_new_message)
    session.execute(update_user_thread)
    session.commit()

  response = {
      'status' : constants.SUCCESS,
      'data' : { 'conversation_thread': [conversation_thread]
       },
      'errors' : None
  }
  if len(convs) == int(limit):
    response['data']['offset'] = int(limit) + int(offset)

  return response  


def update_user_conversation(sender, receiver_id, msg, post_activity=None):

  receiver = util.get_user_by_id(receiver_id)
  if not receiver:
    response = {
        'status' : constants.SUCCESS,
        'data' : None,
        'errors' : {'receiver_id' : constants.INVALID_VALUE}
    }
    return response  

  user_thread = session.query(model.UserThread).\
                          filter(
                                or_( and_( model.UserThread.user_1_id ==receiver.id, model.UserThread.user_2_id == sender.id),
                                  and_( model.UserThread.user_1_id == sender.id, model.UserThread.user_2_id == receiver.id)
                                )
                          ).first()

  if user_thread:
    update_user_thread(user_thread, sender)
  else:
    user_thread = create_user_thread(sender, receiver)

  conversation_thread = update_conversation_thread(msg, user_thread, sender, receiver, post_activity)
  data = {"user_thread_id" : user_thread.id,
          "conversation_thread_id" : conversation_thread.id,  
      }
  response = {
      'status' : constants.SUCCESS,
      'data' : data,
      'errors' : None
  }
  return response 

def mark_conversation_as_read(user_id, dummy_parma=None):
  update_user_thread1 = update(model.UserThread).\
                  where(model.UserThread.user_1_id == user_id ).\
                  values(user_1_new_message = 0)
  session.execute(update_user_thread1)
  session.commit()


  update_user_thread2 = update(model.UserThread).\
                  where(model.UserThread.user_2_id == user_id ).\
                  values(user_2_new_message = 0)
  session.execute(update_user_thread2)
  session.commit()


  response = {
      'status' : constants.SUCCESS,
      'errors' : None
  }
  return response  

def create_user_thread(sender_user, receiver_user):
  user_thread =  model.UserThread()
  user_thread.user_1_id = sender_user.id
  user_thread.user_2_id = receiver_user.id
  user_thread.user_2_new_message = True
  user_thread.modified_date = datetime.datetime.now()
  session.add(user_thread)
  session.commit()
  return user_thread

def update_user_thread(user_thread, sender):
  if sender.id != user_thread.user_1_id:
    user_thread.user_1_new_message = True
    user_thread.user_1_modified_datetime = datetime.datetime.now()
  else:
    user_thread.user_2_new_message = True
    user_thread.user_2_modified_datetime = datetime.datetime.now()

  user_thread.modified_date = datetime.datetime.now()
  if session.is_modified(user_thread):
    session.merge(user_thread)
    session.commit()
  
def update_conversation_thread(msg, user_thread, sender_user, receiver_user, post_activity=None):
  conversation_thread = model.ConversationThread()
  conversation_thread.thread_id = user_thread.id
  conversation_thread.sender_id = sender_user.id
  conversation_thread.receiver_id = receiver_user.id
  conversation_thread.text = msg
  conversation_thread.sent_datetime = datetime.datetime.now()
  conversation_thread.read_datetime = None
  if post_activity and post_activity.id:
    conversation_thread.post_activity_id = post_activity.id

  session.add(conversation_thread)
  session.commit()
  if post_activity:
    content_artist = post_activity.content.user
    if msg:
      notification_msg = '{username}: {content_title} by {artist} - {msg}'.format(
                  username=sender_user.name.title() if sender_user.name else sender_user.username.title(),
                  content_title =post_activity.content.title[0:20].title(),
                  artist=content_artist.name.title() if content_artist.name else content_artist.username.title(),
                  msg=msg.capitalize())
    else:
      notification_msg = 'New Message from {username}\n {content_title} by {artist}'.format(
                  username=sender_user.name.title() if sender_user.name else sender_user.username.title(),
                  content_title =post_activity.content.title[0:20].title(),
                  artist=content_artist.name.title() if content_artist.name else content_artist.username.title())
  else:
    notification_msg = "%s: %s"%(sender_user.name.title() if sender_user.name else sender_user.username.title(), msg[0:20].capitalize())

  taskqueue.add(url='/tasks/notification_for_conversation',
            method='GET',
            queue_name='user-conversation',
            params={'receiver_id': receiver_user.id,
                    'sender_id' : sender_user.id,
                    'sender_name' : sender_user.username,
                    'msg' : notification_msg,
                    'action': constants.USER_CONVERSATION,
                    'thread_id' : user_thread.id,
                  }
            )

  return conversation_thread

def notification_for_conversation(reciver_id, sender_id, notification_params):

  user = util.get_user_by_id(reciver_id)
  notificaion_count = get_unread_updates_count(user)
  notification_params['count'] = notificaion_count
  notification_params['badge'] = notificaion_count
  reciver_id = [int(reciver_id)]
  logging.info(notification_params)
  toggled_receiver_ids, untoggled_receiver_ids = get_user_according_to_notification_toggles(reciver_id, action=constants.ACTIVITY_PRIVATE_MESSAGE)
  if toggled_receiver_ids:
    notification_params['sound'] = constants.IOS_NOTIFICATION_SOUND
    util.send_notification_to_device(toggled_receiver_ids, sender_id, notification_params)

  if untoggled_receiver_ids:
    del notification_params['msg']
    util.send_notification_to_device(untoggled_receiver_ids, sender_id, notification_params)

def get_user_thread_by_id(thread_id):
  user_thread = session.query(model.UserThread).\
                          filter( model.UserThread.id ==thread_id).\
                          first()
  return user_thread


def get_conversation_thread(thread_ids, user, limit, follower_ids):

  DummyConversationThread = aliased(model.ConversationThread, name='dummy_ct')
  conversations = session.query(model.ConversationThread)\
    .outerjoin(
                  (DummyConversationThread, and_ (
                                                  model.ConversationThread.thread_id == DummyConversationThread.thread_id,
                                                  model.ConversationThread.sent_datetime < DummyConversationThread.sent_datetime
                                                 )
              )).\
    filter(and_(
                  DummyConversationThread.sent_datetime == None,
                  model.ConversationThread.thread_id.in_(thread_ids) 
                )
          ).all() 

  conv_thread_obj = {}

  post_activitie_ids = [int(conv.post_activity_id) for conv in conversations if conv.post_activity_id]
  logging.info(post_activitie_ids)
  conversation_dict = get_user_private_message(user, post_activitie_ids, follower_ids=follower_ids, like_required=False)

  for post_activity_id, private_message in conversation_dict.items():
    logging.info("post_activity_id : %s ---- >   %s"%(post_activity_id, private_message))

  for conv in conversations:
    if conv.post_activity_id and not conversation_dict.has_key(int(conv.post_activity_id)):
      pass
    else:
      if conv.thread_id not in conv_thread_obj:
        conv_thread_obj[conv.thread_id] = []
      con_obj = api_serialize.conversation_to_dictionary(conv)
      if conv.post_activity_id:
        con_obj["private_message"] = [conversation_dict[int(conv.post_activity_id)]]
      conv_thread_obj[conv.thread_id].append(con_obj )
  return conv_thread_obj

def get_user_all_conversation(user, limit, next_datetime=None, prev_datetime=None, follower_ids=None):
  al_user_1 = aliased(model.User, name='users_1')
  al_user_2 = aliased(model.User, name='users_2')

  user_threads = session.query(model.UserThread, al_user_1, al_user_2).\
                      options(
                        Load(al_user_1).load_only("id", "username", "name", "user_type", "s3_compressed_image_key", "s3_blur_image_key", "s3_short_image_key", "s3_short_blur_image_key"),
                      ).\
                      options(
                        Load(al_user_2).load_only("id", "username", "name", "user_type", "s3_compressed_image_key", "s3_blur_image_key", "s3_short_image_key", "s3_short_blur_image_key"),
                      ).\
                      join(al_user_1, and_(
                            al_user_1.id == model.UserThread.user_2_id, al_user_1.is_active == 1
                          )
                      ).\
                      join(al_user_2, and_(
                            al_user_2.id == model.UserThread.user_1_id, al_user_2.is_active == 1
                          )
                      ).\
                      filter( or_( model.UserThread.user_1_id == user.id , model.UserThread.user_2_id == user.id ) ).\
                      filter( al_user_1 != None).\
                      filter( al_user_2 != None)

  if next_datetime:
    user_threads = user_threads.filter( model.UserThread.modified_date < next_datetime )

  if prev_datetime:
    user_threads = user_threads.filter( model.UserThread.modified_date > prev_datetime )

  user_threads = user_threads.order_by(desc(model.UserThread.modified_date)).limit(limit).all()

  thread_ids = [thread.UserThread.id for thread in user_threads]
  conversations = get_conversation_thread(thread_ids, user, 1, follower_ids)

  data_obj = []
  for thread in user_threads:
    if thread.UserThread.id in conversations:
      data = {}
      data["added_date"] = gtools.dt_to_timestamp( thread.UserThread.modified_date )
      data["thread_id"] = thread.UserThread.id
      data["user_1"] = [api_serialize.user_to_dictionary(thread.users_1, follower_ids=follower_ids) ]
      data["user_2"] = [api_serialize.user_to_dictionary(thread.users_2, follower_ids=follower_ids) ]
      data["activity_type"] = constants.EVENT_FOR_USER_CONVERSATION
      data["conversation"] = conversations[thread.UserThread.id]
      data_obj.append(data)
    #TODO Done in task queue

  taskqueue.add(url='/tasks/read_conversation',
            method='POST',
            params={
                    "user_id" : user.id , 
                  }
            )
    #mark_conversation_as_read(user, thread.UserThread.id)
  return data_obj

def get_user_private_message(user, post_activity_ids, follower_ids=None, like_required=True):
  post_activities = session.query(model.PostActivity, model.User, model.Content).\
                          options(
                            joinedload(model.PostActivity.post_user).load_only("id", "username", "name", "user_type", "s3_compressed_image_key", "s3_blur_image_key", "s3_short_image_key", "s3_short_blur_image_key"),
                          ).\
                          options(
                            Load(model.Content).load_only("id", "title", "duration", "play_count", "content_type", "genre_id", "album_id", "user_id", "s3_Key", "format", "video_frame", "is_converted", "video_frame_width", "video_frame_height", "s3_Key_before_convert", "has_lyrics", "short_video_frame"),
                          ).\
                          options(
                            joinedload(model.Content.album).load_only("id", "album_name", "s3_compressed_image_key", "s3_blur_image_key", "s3_short_image_key", "s3_short_blur_image_key"),
                          ).\
                          options(
                            joinedload(model.Content.user).load_only("id", "username", "name", "user_type", "s3_compressed_image_key", "s3_blur_image_key", "s3_short_image_key", "s3_short_blur_image_key"),
                          ).\
                          options(
                            Load(model.User).load_only("id", "username", "name", "user_type", "s3_compressed_image_key", "s3_blur_image_key", "s3_short_image_key", "s3_short_blur_image_key"),
                          ).\
                          join(model.User, and_(model.User.id == model.PostActivity.user_id ) ).\
                          join(model.Content, and_( model.Content.id == model.PostActivity.content_id,
                                                    model.Content.is_hidden ==0 ) ).\
                          filter(model.PostActivity.id.in_(post_activity_ids)).\
                          filter(model.PostActivity.activity_type == constants.ACTIVITY_PRIVATE_MESSAGE ).\
                          group_by(model.PostActivity.id).\
                          order_by(desc(model.PostActivity.added_date)).all()
  notifications = []
  content_ids = [int(post_activity.Content.id) for post_activity in post_activities]
  liked_contents = util.get_content_likes(user, content_ids) if like_required else None

  for post_activity in post_activities:
    notification_data = {
      "post_activity_id" : post_activity.PostActivity.id,
      "activity_type" : post_activity.PostActivity.activity_type,
      "activity_user" : [api_serialize.user_to_dictionary(post_activity.User, follower_ids=follower_ids)],
      "added_date" : gtools.dt_to_timestamp(post_activity.PostActivity.added_date),
    }
    if post_activity.PostActivity.activity_type == constants.ACTIVITY_PRIVATE_MESSAGE:
      notification_data["comment"] = post_activity.PostActivity.comment

    # if post have content then add content dict in notification
    if post_activity.Content:
      notification_data["content"] = [api_serialize.content_to_dictionary(post_activity.Content, follower_ids=follower_ids, video_frame_url=post_activity.Content.video_frame, liked_contents=liked_contents)]

    if post_activity.PostActivity.post_user:
      notification_data["post_user"] = [ api_serialize.user_to_dictionary(post_activity.PostActivity.post_user, follower_ids=follower_ids)]

    notifications.append(notification_data)

  notification_dict = {}
  for notification in notifications:
    if notification_dict.has_key(int(notification['post_activity_id'])):
      notification_dict[int(notification['post_activity_id'])].append(notification)
    else:
      notification_dict[int(notification['post_activity_id'])] = notification
  return notification_dict

def send_notification_to_follower(follower_id, following_ids):
  follower = util.get_user_by_id(follower_id)
  following_ids = [ int(user_id) for user_id in following_ids.split(",") ]
  toggled_following_ids, untoggled_following_ids = get_user_according_to_notification_toggles(following_ids, action=constants.FOLLOW_YOU)

  follower_name = follower.name.title() if follower.name else follower.username.title()
  notifi_params = {
                     'activity' : constants.USER_NOTIFICATION,
                     'user_id': follower.id,
                     'user_type': follower.user_type,
                     'username' : follower_name,
                    }

  if toggled_following_ids:
    notifi_params['msg'] = "%s followed you"%follower_name
    notifi_params['sound'] = constants.IOS_NOTIFICATION_SOUND
    followings = session.query(model.User).filter(model.User.id.in_(toggled_following_ids)).all()
    for following in followings:
      notification_count = get_unread_updates_count(following)
      notifi_params['badge'] = notification_count
      notifi_params['count'] = notification_count
      notifi_params['following_count'] = following.following_count
      notifi_params['follower_count'] = following.follower_count
      util.send_notification_to_device(receiver_ids=[int(following.id)], sender_id=follower.id, notification_params=notifi_params)

  if untoggled_following_ids:
    followings = session.query(model.User).filter(model.User.id.in_(untoggled_following_ids)).all()
    for following in followings:
      notification_count = get_unread_updates_count(following)
      notifi_params['badge'] = notification_count
      notifi_params['count'] = notification_count
      notifi_params['following_count'] = following.following_count
      notifi_params['follower_count'] = following.follower_count
    util.send_notification_to_device(receiver_ids=[int(following.id)], sender_id=follower.id, notification_params=notifi_params)

def send_notification_to_unlike_post(user_id, post_id, post_activity_id):
  post = util.get_post_by_id(post_id)
  notifi_params = {
    'user_id' : int(user_id),
    'post_id' : int(post.id),
    'post_activity_id' : int(post_activity_id),
    'activity' : constants.UNLIKE
  }
  util.send_notification_to_device([post.user_id], sender_id=user_id, notification_params=notifi_params)

def send_notification_to_post(user_id, post_id, shared_user_ids, action, post_activity_id=None):
  user = util.get_user_by_id(user_id)
  notifi_params = {}
  user_name = user.name.title() if user.name else user.username.title()
  if action == constants.ACTIVITY_LIKE:
    post = session.query( model.Post).\
                  options( Load(model.Post).load_only("id", "added_date", "content_id") ).\
                  options( joinedload(model.Post.playlist).load_only("id", "name") ).\
                  filter( model.Post.id == post_id).first()

    notifi_params['msg'] = "%s liked your post"%user_name
    notifi_params['post_event_type'] = post.event_type
    if post.playlist:
      notifi_params['playlist_id'] = post.playlist.id
      notifi_params['playlist_name'] = post.playlist.name
    toggled_receiver_ids, untoggled_receiver_ids = get_user_according_to_notification_toggles([post.user_id], action=constants.ACTIVITY_LIKE)

  elif action == constants.ACTIVITY_COMMENT:
    post = util.get_post_by_id(post_id)
    post_activity = util.get_post_activity_by_id(post_activity_id)
    comment = post_activity.comment[:30] + "..." if len(post_activity.comment)>30 else post_activity.comment
    notifi_params['msg'] = "%s commented: %s"%(user_name, comment)
    notifi_params['post_event_type'] = post.event_type
    toggled_receiver_ids, untoggled_receiver_ids = get_user_according_to_notification_toggles([post.user_id], action=constants.ACTIVITY_COMMENT)

  """
  elif action == constants.ACTIVITY_PRIVATE_MESSAGE:
    notifi_params['msg'] = "%s sent you a private message"%(user_name)
    receiver_ids = [ int(user_id) for user_id in shared_user_ids.split(",") ] if shared_user_ids else []
  """
  notifi_params['post_id'] = post_id
  notifi_params['activity'] = constants.UPDATE_NOTIFICATION
  notification_count = get_unread_updates_count(post.user)
  notifi_params['count'] = notification_count
  notifi_params['badge'] = notification_count

  if toggled_receiver_ids:
    notifi_params['sound'] = constants.IOS_NOTIFICATION_SOUND
    logging.info(notifi_params)
    util.send_notification_to_device(toggled_receiver_ids, sender_id=user.id, notification_params=notifi_params)

  if untoggled_receiver_ids:
    del notifi_params['msg']
    logging.info(notifi_params)
    util.send_notification_to_device(untoggled_receiver_ids, sender_id=user.id, notification_params=notifi_params)

def send_notification_for_contact_add(user_id):
  user = util.get_user_by_id(user_id)
  contacts = get_users_has_contact(user) 
  if contacts:
    contact_names = {}
    receiver_ids = []
    for contact in contacts:
      receiver_ids.append(int(contact.user_id))
      contact_names[int(contact.user_id)] = contact.name
    toggled_receiver_ids, untoggled_receiver_ids = get_user_according_to_notification_toggles(receiver_ids, constants.CONTACT_JOIN)
    user_name = user.name.title() if user.name else user.username.title()
    notifi_params = {'activity' : constants.CONTACT_JOIN,
                  'user_id' : user.id,
                  'user_type' : user.user_type,
                  'username' : user_name,
                  }

    if untoggled_receiver_ids:
      util.send_notification_to_device(untoggled_receiver_ids, sender_id=user.id, notification_params=notifi_params)

    if toggled_receiver_ids:
      notifi_params['sound'] = constants.IOS_NOTIFICATION_SOUND
      for receiver_id in toggled_receiver_ids:
        notifi_params['msg'] = "Your contact %s joined Veromuse as %s, follow them"%(contact_names[receiver_id], user_name)
        util.send_notification_to_device([receiver_id], sender_id=user.id, notification_params=notifi_params)

def get_users_has_contact(user):
    contact_number = user.country_code + user.contact_number
    contacts = session.query(model.Contact.id, model.Contact.user_id, model.Contact.name).\
                        filter(model.Contact.contact_number == contact_number).all()
    logging.info(contacts)
    return contacts

def send_notification_for_facebook_contact(user_id):
  user = util.get_user_by_id(user_id)
  facebook_friends = get_users_has_facebook_contact_for(user)
  receiver_ids = [ int(friend.user_id) for friend in facebook_friends ]
  logging.info("friends ids : %s"%receiver_ids)
  user_name = user.name.title() if user.name else user.username.title()
  toggled_receiver_ids, untoggled_receiver_ids = get_user_according_to_notification_toggles(receiver_ids, constants.FACEBOOK_JOIN)
  notifi_params = {'activity' : constants.FACEBOOK_JOIN,
                'user_id' : user.id,
                'user_type' : user.user_type,
                'username' : user_name,
                }
  if untoggled_receiver_ids:
    util.send_notification_to_device(untoggled_receiver_ids, sender_id=user.id, notification_params=notifi_params)

  if toggled_receiver_ids:
    notifi_params['sound'] = constants.IOS_NOTIFICATION_SOUND
    notifi_params['msg'] = "Your facebook contact %s joined Veromuse as %s, follow them"%(user.fb_name, user_name)
    util.send_notification_to_device(toggled_receiver_ids, sender_id=user.id, notification_params=notifi_params)

def send_notification_for_twitter_contact(user_id):
  user = util.get_user_by_id(user_id)
  twitter_friends = get_users_has_twitter_contact_for(user)
  receiver_ids = [ int(friend.user_id) for friend in twitter_friends ]
  toggled_receiver_ids, untoggled_receiver_ids = get_user_according_to_notification_toggles(receiver_ids, constants.TWITTER_JOIN)
  user_name = user.name.title() if user.name else user.username.title()
  notifi_params = {'activity' : constants.TWITTER_JOIN,
                'user_id' : user.id,
                'user_type' : user.user_type,
                'username' : user_name,
                }
  if untoggled_receiver_ids:
    util.send_notification_to_device(untoggled_receiver_ids, sender_id=user.id, notification_params=notifi_params)

  if toggled_receiver_ids:
    notifi_params['sound'] = constants.IOS_NOTIFICATION_SOUND
    notifi_params['msg'] =  "Your twitter contact %s joined Veromuse as %s, follow them"%(user.twitter_name, user_name)
    util.send_notification_to_device(toggled_receiver_ids, sender_id=user.id, notification_params=notifi_params)

def get_users_has_twitter_contact_for(user):
  twitter_friends = session.query(model.SocialNetwork.id, model.SocialNetwork.user_id).\
                        filter(model.SocialNetwork.network_id == user.twitter_id).\
                        filter(model.SocialNetwork.user_id != user.id).\
                        all()
  return twitter_friends

def get_users_has_facebook_contact_for(user):
  facebook_friends = session.query(model.SocialNetwork.id, model.SocialNetwork.user_id).\
                        filter(model.SocialNetwork.facebook_public_id == user.fb_id).\
                        filter(model.SocialNetwork.user_id != user.id).\
                        all()
  return facebook_friends

def get_user_notification_toggles(user):
  user_notification_obj = get_user_notification(user)
  logging.info(user_notification_obj) 
  if user_notification_obj:
    user_notification_toggles = {
      "like_toggle" : user_notification_obj.like_toggle,
      "comment_toggle" : user_notification_obj.comment_toggle,
      "contact_join_toggle" : user_notification_obj.contact_join_toggle,
      "facebook_join_toggle" : user_notification_obj.facebook_join_toggle,
      "twitter_join_toggle" : user_notification_obj.twitter_join_toggle,
      "private_message_toggle" : user_notification_obj.private_message_toggle,
      "unsubscribe_email_toggle" : user_notification_obj.unsubscribe_email_toggle,
      "follower_toggle" : user_notification_obj.follower_toggle,
    }
  else:
    notification_toggles = model.UserNotificationToggles()
    notification_toggles.user_id = user.id
    notification_toggles.follower_toggle = True
    notification_toggles.like_toggle = True
    notification_toggles.comment_toggle = True
    notification_toggles.contact_join_toggle = True
    notification_toggles.facebook_join_toggle = True
    notification_toggles.twitter_join_toggle = True
    notification_toggles.private_message_toggle = True
    notification_toggles.unsubscribe_email_toggle = False
    session.add(notification_toggles)
    session.commit()
    user_notification_toggles = {
      "like_toggle" : notification_toggles.like_toggle,
      "comment_toggle" : notification_toggles.comment_toggle,
      "contact_join_toggle" : notification_toggles.contact_join_toggle,
      "facebook_join_toggle" : notification_toggles.facebook_join_toggle,
      "twitter_join_toggle" : notification_toggles.twitter_join_toggle,
      "private_message_toggle" : notification_toggles.private_message_toggle,
      "unsubscribe_email_toggle" : notification_toggles.unsubscribe_email_toggle,
      "follower_toggle" : notification_toggles.follower_toggle,
    }

  response = {
      'status' : constants.SUCCESS,
      'data' : {"user_notification_toggles": user_notification_toggles},
      'errors' : None
  }
  return response

def update_user_notification_toggles(user, params):
  notification_toggles = get_user_notification(user)
  if notification_toggles:
    if params['follower_toggle']:
      notification_toggles.follower_toggle = gtools.str_to_bool( params['follower_toggle'] )

    if params['like_toggle']:
      notification_toggles.like_toggle = gtools.str_to_bool( params['like_toggle'] )

    if params['comment_toggle']:
      notification_toggles.comment_toggle = gtools.str_to_bool( params['comment_toggle'] )

    if params['contact_join_toggle']:
      notification_toggles.contact_join_toggle = gtools.str_to_bool( params['contact_join_toggle'] )

    if params['facebook_join_toggle']:
      notification_toggles.facebook_join_toggle = gtools.str_to_bool( params['facebook_join_toggle'] )

    if params['twitter_join_toggle']:
      notification_toggles.twitter_join_toggle = gtools.str_to_bool( params['twitter_join_toggle'] )

    if params['private_message_toggle']:
      notification_toggles.private_message_toggle = gtools.str_to_bool( params['private_message_toggle'] )

    if params['unsubscribe_email_toggle']:
      notification_toggles.unsubscribe_email_toggle = gtools.str_to_bool( params['unsubscribe_email_toggle'] )

    session.add(notification_toggles)
    session.commit()
  else:
    notification_toggles = model.UserNotificationToggles()
    notification_toggles.user_id = user.id
    notification_toggles.follower_toggle = True
    notification_toggles.like_toggle = True
    notification_toggles.comment_toggle = True
    notification_toggles.contact_join_toggle = True
    notification_toggles.facebook_join_toggle = True
    notification_toggles.twitter_join_toggle = True
    notification_toggles.private_message_toggle = True
    notification_toggles.unsubscribe_email_toggle = False
    session.merge(notification_toggles)
    session.commit()

  response = {
      'status' : constants.SUCCESS,
      'data' : {"msg": "user notification updated successfully."},
      'errors' : None
  }
  return response

def get_user_notification(user):
  user_notification_toggles = session.query(model.UserNotificationToggles).filter(model.UserNotificationToggles.user_id==user.id).first()
  return user_notification_toggles

def get_unread_updates_count(user=None, is_own=False):
  activities_list = [constants.ACTIVITY_LIKE, constants.ACTIVITY_COMMENT]
  unread_conversation_count = session.query( func.count(model.UserThread.id).label('notification_count')).\
                          filter( 
                            or_(
                              and_( model.UserThread.user_1_id == user.id, 
                                model.UserThread.user_1_new_message == True),
                              and_( model.UserThread.user_2_id == user.id, 
                                model.UserThread.user_2_new_message == True)
                            )
                          ).first()

  if is_own:
    unread_post_activity_count = session.query( func.count(model.PostActivity.id).label('notification_count')).\
                            filter(and_(model.PostActivity.user_id == user.id,
                                        model.PostActivity.is_viewed == False,
                                        model.PostActivity.activity_type.in_(activities_list)
                            )).first()
  else:
    unread_post_activity_count = session.query( func.count(model.PostActivity.id).label('notification_count')).\
                            filter(and_(
                                        or_(
                                            and_(
                                                model.PostActivity.post_user_id == user.id,
                                                model.PostActivity.activity_type.in_(activities_list)
                                            ),
                                            and_(
                                                model.PostActivity.user_id == user.id,
                                                model.PostActivity.activity_type == constants.ACTIVITY_FOLLOW
                                            ),
                                        ),
                                        model.PostActivity.is_viewed == False,
                            )).first()
  count = unread_post_activity_count.notification_count + unread_conversation_count.notification_count
  logging.info("============================= count ==============================")
  logging.info(count)
  return count

def get_artist_page(user, artist_page_id):
  response = {
      "status" : constants.ERROR,
      "errors" : None,
      "data" : None
  }
  try:
    artist_page = session.query(model.ArtistData).filter(model.ArtistData.id == artist_page_id).first()
    if not artist_page:
      response["errors"] = {"error" : constants.INVALID_VALUE}
      return response
    response['data'] = {
          "artist_page" : [api_serialize.artist_page_data_to_dictionary(artist_page, image_info_required=True)]
    }
    response['status'] = constants.SUCCESS
  except Exception as e:
    logging.exception(e)
    response['errors'] =  {"error":"Failed to fetch data from database."}
  return response

def save_user_image_on_s3(image_data, user, s3_bucket=constants.USER_IMAGES_BUCKET, s3_key=None):
  img_format = constants.IMAGE_FORMATS[ gap_image.Image(image_data).format ].lower()
  logging.info(img_format)

  if not s3_key or s3_key in constants.USER_DEFAULT_IMAGES:
    s3_key = gtools.ignore_special_charecter(user.username)+"_"+str(util.get_unique_key()) +"_"+ str(user.id) +"."+img_format
  s3_key= s3_key.replace(" ","")
  image_key = boto_lib.save_img_in_s3(image_data, s3_key, s3_bucket)
  return image_key


def change_user_profile_picture(user, profile_image):
  response = {
        "status" : constants.ERROR,
        "data" : None,
        "errors" : None
  }
  try:
    logging.info("########## changing the profile image from mobile ######")
    s3_bucket=constants.USER_IMAGES_BUCKET
    old_s3_key = user.s3_image_key
    old_s3_rescale_image_key = user.s3_rescale_image_key
    old_compressed_image_key = user.s3_compressed_image_key
    old_short_image_key = user.s3_short_image_key
    img_format = constants.IMAGE_FORMATS[gap_image.Image(profile_image).format].lower()

    filtered_user_name = gtools.ignore_special_charecter(user.username)
    # upload origional image to s3
    s3_key = filtered_user_name+"_"+str(util.get_unique_key()) +"_"+ str(user.id) +"."+img_format
    s3_key = save_user_image_on_s3(profile_image, user, s3_bucket=s3_bucket, s3_key=s3_key)

    # upload rescale image to s3
    rescale_image = util.rescale(profile_image, width=141, height=141)
    rescale_image_s3_key = filtered_user_name+"_rescale_"+str(util.get_unique_key()) +"_"+ str(user.id) +"."+img_format
    rescale_image_s3_key = boto_lib.save_img_in_s3(rescale_image, rescale_image_s3_key, s3_bucket=s3_bucket)

    user.s3_image_key = s3_key
    user.s3_rescale_image_key = rescale_image_s3_key
    user.s3_compressed_image_key = None
    user.s3_short_image_key = None
    session.merge(user)
    session.commit()
  
    logging.info(old_s3_key)
    if not old_s3_key in constants.USER_DEFAULT_IMAGES:
      logging.info("Deleting old images for user %s ."%user.username)
      boto_lib.delete_image_from_s3(s3_bucket, old_s3_key)
      boto_lib.delete_image_from_s3(s3_bucket, old_s3_rescale_image_key)

    if old_compressed_image_key:
      if not "compressed_default_user_image_" in old_compressed_image_key:
        boto_lib.delete_image_from_s3(constants.USER_IMAGES_BUCKET, old_compressed_image_key)

    if old_short_image_key:
      boto_lib.delete_image_from_s3(constants.USER_IMAGES_BUCKET, old_short_image_key)

    gae_session = gaesessions.get_current_session()
    send_request_to_update_compressed_user_image(user, device_id=gae_session["device_id"])
    profile_image = boto_lib.get_image_url(constants.USER_IMAGES_BUCKET, user.s3_image_key) if user.s3_image_key else None
    response["status"] = constants.SUCCESS
    
    response["data"]  = {"profile_image" : profile_image}
  except Exception, e:
    logging.error(e)
    response["errors"] = {"error" : "Something went wrong with change image."}
  logging.info("change image response :: %s"%response)
  return  response


def get_user_according_to_notification_toggles(reciver_ids, action):
  logging.info(reciver_ids)
  users_list = session.query(model.User, model.UserNotificationToggles).\
                 options(
                    Load(model.User).load_only("id"),
                 ).\
                 outerjoin(model.UserNotificationToggles, and_(model.UserNotificationToggles.user_id == model.User.id) ).\
                 filter( model.User.id.in_(reciver_ids) ).all()

  toggled_user_ids = []
  for user in users_list:
    if user.UserNotificationToggles and user.UserNotificationToggles.like_toggle == True and action == constants.ACTIVITY_LIKE:
      toggled_user_ids.append(user.User.id)
    elif user.UserNotificationToggles and user.UserNotificationToggles.comment_toggle == True and action == constants.ACTIVITY_COMMENT:
      toggled_user_ids.append(user.User.id)
    elif user.UserNotificationToggles and user.UserNotificationToggles.follower_toggle == True and action == constants.FOLLOW_YOU:
      toggled_user_ids.append(user.User.id)
    elif user.UserNotificationToggles and user.UserNotificationToggles.contact_join_toggle == True and action == constants.CONTACT_JOIN:
      toggled_user_ids.append(user.User.id)
    elif user.UserNotificationToggles and user.UserNotificationToggles.facebook_join_toggle == True and action == constants.FACEBOOK_JOIN:
      toggled_user_ids.append(user.User.id)
    elif user.UserNotificationToggles and user.UserNotificationToggles.twitter_join_toggle == True and action == constants.TWITTER_JOIN:
      toggled_user_ids.append(user.User.id)
    elif user.UserNotificationToggles and user.UserNotificationToggles.private_message_toggle == True and action == constants.ACTIVITY_PRIVATE_MESSAGE:
      toggled_user_ids.append(user.User.id)

    if not user.UserNotificationToggles and action in [constants.ACTIVITY_COMMENT, constants.ACTIVITY_LIKE, constants.FOLLOW_YOU, constants.CONTACT_JOIN , constants.FACEBOOK_JOIN, constants.TWITTER_JOIN, constants.ACTIVITY_PRIVATE_MESSAGE]:
      toggled_user_ids.append(user.User.id)

  untoggled_user_ids = []
  for reciver_id in reciver_ids:
    if reciver_id not in toggled_user_ids:
      untoggled_user_ids.append(reciver_id)

  logging.info("toggled_user_ids  ::  %s" % toggled_user_ids)
  logging.info("untoggled_user_ids  ::  %s" % untoggled_user_ids)
  return toggled_user_ids, untoggled_user_ids


def notification_for_un_follow(receiver_user_id, sender_id):
  reciver_ids = [int(receiver_user_id)]
  #reciver_ids = get_user_according_to_notification_toggles(reciver_ids, action=constants.ACTIVITY_PRIVATE_MESSAGE)
  user = session.query(model.User.id, model.User.following_count, model.User.follower_count).filter(model.User.id == int(receiver_user_id)).first()

  notification_params= {
    'activity' : constants.UNFOLLOW,
    'user_id' : sender_id,
    'following_count' : user.following_count,
    'follower_count' : user.follower_count
  }
  util.send_notification_to_device(reciver_ids, sender_id, notification_params)

def notification_for_change_profile_image(receiver_user_id, profile_image, device_id):
  receiver_ids = [int(receiver_user_id)]
  notification_params = {
    "profile_image" : profile_image,
    "msg" : "Your profile picture updated successfully.",
  }
  util.send_notification_to_self_device(receiver_ids, notification_params, device_id=device_id)

def notification_for_update_user_profile(receiver_user_id, params, device_id=None):
  receiver_ids = [int(receiver_user_id)]
  notification_params = {
      "user_update" : {"activity_type" : int(params['activity_type'])},
  }
  if params['profile_image']:
    notification_params["user_update"]["profile_image"] = str(params['profile_image'])
  if params['name'] !=None:
    notification_params["user_update"]["name"] = str(params['name'])
  if params['user_type'] != None:
    notification_params["user_update"]["user_type"] = int(params['user_type'])
  if params['username']:
    notification_params["user_update"]["username"] = str(params['username'])
  if params['artist_page_id']:
    notification_params["user_update"]["artist_page_id"] = int(params['artist_page_id'])
  if params['album_name']:
    notification_params["user_update"]["album_name"] = str(params['album_name'])
  if params['content_id']:
    notification_params["user_update"]["content_id"] = int(params['content_id'])
  if params['album_id']:
    notification_params["user_update"]["album_id"] = int(params['album_id'])
  if params['title']:
    notification_params["user_update"]["title"] = str(params['title'])
  if params['lyrics_updated']:
    notification_params["user_update"]["lyrics_updated"] = params['lyrics_updated']
  if params['album_updated']:
    notification_params["user_update"]["album_updated"] = params['album_updated']
  if params['genre_updated']:
    notification_params["user_update"]["genre_updated"] = params['genre_updated']
  if params['video_frame']:
    notification_params["user_update"]["video_frame"] = str(params['video_frame'])

  util.send_notification_to_self_device(receiver_ids, notification_params, device_id)

def notification_for_update_settings(user, activity_type, profile_image, name=None, username=None, device_id=None):
  task_params =  { 
                'receiver_id': user.id,
                'activity_type' : activity_type,
                'device_id' : device_id,
      }
  if profile_image:
    task_params['profile_image'] = profile_image
  if name != None:
    task_params['name'] = name
  if username:
    task_params['username'] = username
  if username or name or profile_image:
    taskqueue.add(url='/tasks/notification_for_user_profile_update',
        method='POST',
        queue_name='notifiation-to-device',
        params= task_params)

def get_cluster_member_count(user):
  cluster = session.query(model.Cluster.user_count).\
                  join(model.ClusterUser, model.ClusterUser.user_id == user.id).\
                  filter(model.Cluster.id == model.ClusterUser.cluster_id).first()
  cluster_member_count = cluster.user_count if cluster else None
  return cluster_member_count

def get_user_metadata(user):
  data = {
          'updates_count': get_unread_updates_count(user),
          'cluster_member_count': get_cluster_member_count(user),
          'user' : [{
                      'fb_name' : user.fb_name,
                      'twitter_name' : user.twitter_name,
                      'follower_count': user.follower_count,
                      'following_count': user.following_count,
                      'fb_toggle': user.fb_toggle,
                      'twitter_toggle': user.twitter_toggle,
                      'fb_id': user.fb_id,
                      'twitter_id': user.twitter_id,
                      'facebook_token': user.facebook_token,
                      'twitter_token': user.twitter_token,
                      'twitter_secret': user.twitter_secret,
                      'is_launch_complete' : user.is_launch_complete,
                      'is_sync_contacts' : user.is_sync_contacts,
                      'facebook_user_permission' : user.facebook_user_permission,
                      'is_email_verified' : user.is_email_verified,
                      'is_verification_required' : user.is_verification_required,
                      'is_first_device_login' : user.is_first_device_login,
                      'add_playlist_toggle' : user.add_playlist_toggle,
                      'is_rating_visited' : user.is_rating_visited,
                      'playlist_id' : user.playlist_id,
              }]
  }
  response = {
      "status" : constants.SUCCESS,
      "errors" : None,
      "data" : data
  }
  logging.info(response)
  return response

def save_supportlog_image_on_s3(image_data, user, s3_bucket=constants.ALBUM_IMAGES_BUCKET, s3_key=None):
  img_format = constants.IMAGE_FORMATS[ images.Image(image_data).format ].lower()
  logging.info(img_format)
  if not s3_key:
    s3_key = user.username+"_support_"+str(util.get_unique_key()) +"_"+ str(user.id) +"."+img_format
  s3_key = s3_key.replace(" ", "")
  image_key = boto_lib.save_img_in_s3(image_data, s3_key, s3_bucket)
  return image_key

def get_total_artist_count():
  response = {
      "status" : constants.SUCCESS,
      "errors" : None,
      "data" : {"artist_count" : util.artist_count()}
  }
  logging.info(response)
  return response

def update_follow_details(params):
  following = session.query(model.Followers.follower_id, func.count(model.Followers.id).label('following_count')).\
                  join(model.User, and_(model.User.is_active == 1, model.Followers.user_id == model.User.id)).\
                  filter(model.Followers.follower_id == int(params['follower_id'])).group_by(model.Followers.follower_id).\
                  first()

  following_count = following.following_count if following else 0

  stmt = update(model.User).where(model.User.id==int(params['follower_id'])).values(following_count = following_count)
  result =  session.execute(stmt)
  session.commit()

  following_ids = map(int, params['following_ids'].split(","))
  logging.info("following_ids :: %s"%following_ids)
  followers = session.query(model.Followers.user_id, func.count(model.Followers.id).label('follower_count')).filter(model.Followers.user_id.in_(following_ids)).group_by(model.Followers.user_id).all()

  user_ids = [follower.user_id for follower in followers]
  logging.info("followers :: %s"%user_ids)
  for user_id in following_ids:
    if user_id not in user_ids:
      logging.info("updateting follower id  :: %s"%user_id)
      stmt = update(model.User).where(model.User.id == user_id).values(follower_count = 0)
      result =  session.execute(stmt)
      session.commit()
      
  for follower in followers:
    stmt = update(model.User).where(model.User.id==follower.user_id).values(follower_count = follower.follower_count)
    result =  session.execute(stmt)
    session.commit()

  if params['action'] == constants.FOLLOW_ARTIST:
    taskqueue.add(url='/tasks/send_notifiation_to_device',
              method='GET',
              queue_name='notifiation-to-device',
              params={
                      "following_ids" : params['following_ids'],
                      "follower_id" : params['follower_id'],
                      "action" : constants.FOLLOW_ARTIST,
                    }
              )
    ds_user_component.update_ds_users_for_follow(params['follower_id'], params['following_ids'])

  elif params['action'] == constants.UNFOLLOW_ARTIST:    
    taskqueue.add(url='/tasks/notification_for_unfollow',
              method='GET',
              queue_name='notification-for-unfollow',
              params={'receiver_id': params['following_ids'],
                      'sender_id' : params['follower_id'],
                    }
              )
    ds_user_component.update_ds_users_for_unfollow(params['follower_id'], params['following_ids'])

def update_device_info(user, params):
  response = {
        "status":constants.ERROR,
        "data":None,
        "errors":None,
  }

  if params["device_id"]:
    gae_session = gaesessions.get_current_session()
    if gae_session.is_active() and gae_session['user_id'] == int(user.id):
      gae_session['device_id'] = params["device_id"]
      gae_session['device_type'] = params["device_type"]
      gae_session.save()
      sessionObj = gaesessions.SessionModel.get(Key.from_path('SessionModel', gae_session.sid))
      old_sessionObj=gaesessions.SessionModel.all().filter("__key__ !=", sessionObj).filter("device_id", params["device_id"]).fetch(1000)
      logging.info("Deleting old session")

      for device in old_sessionObj:
        logging.info(device.key().name())
        device.delete()
      sessionObj.device_id = params["device_id"]
      sessionObj.device_type = params["device_type"]
      sessionObj.put()
      
      user_signup_by = util.get_user_signup(params["device_type"])
      if user_signup_by and user_signup_by != user.signup_by:
        user.signup_by = user_signup_by
        session.merge(user)
        session.flush()
        session.commit()

      response["status"] = constants.SUCCESS
      response["data"] = {"msg":"Device id saved successfully."}
  else:
    response["errors"] = {"device_id":constants.PARAM_REQUIRED}
  return response

def check_login_detail(params):
  response = {
    "status" : constants.ERROR,
    "errors" : None,
    "data": None
  }
  if params['email'] and params['password']:
    user = util.get_user_by_email(params['email'])
    if not user:
      user = util.get_user_by_name(params['email'])

    if user and user.is_active and auth.check_password(params['password'], user.password):
      response["status"] = constants.SUCCESS
      return response

  return response

def update_user_follow_detail(user, params):
  response = {
      "status" : constants.ERROR,
      "data":None,
      "errors":None
  }
  logging.info(params['register_follower'])
  logging.info("following id :: " + str(params['following_id']))
  if params['register_follower']:
    res = register_follower(user, params['following_id'])
    msg = "Follow user successfully."
  else:
    res = un_register_follower(user, params['following_id'])
    msg = "Unfollow user successfully."
  if res["status"]:
    response["status"] = constants.SUCCESS
    response["data"] = {"msg":msg}
  else:
    response["errors"] = {"msg":"Something went wrong."}
  return response

def send_request_to_update_compressed_user_image(user, device_id=None):
   taskqueue.add(url='/tasks/upload_user_compressed_image',
      method='GET',
      queue_name='optimize-queue',
      params={
            "user_id" : str(user.id),
            "device_id" : device_id
          }
    )

def update_user_compressed_image(user, device_id=None):
  urlfetch.set_default_fetch_deadline(100)
  if not user.s3_image_key:
    logging.info("user does not contain any image.")
    return

  image_url = boto_lib.get_image_url(constants.USER_IMAGES_BUCKET, user.s3_image_key)
  s3_response = urlfetch.fetch(image_url)
  if not (s3_response and s3_response.status_code == 200):
    logging.error("image is not loaded successfully.")
    return

  image_data = s3_response.content
  rescale_image = util.rescale_image(image_data, max_width=540)
  short_image = util.rescale_image(image_data, max_width=90)
  
  # uploading the rescale image on s3
  img_format = constants.IMAGE_FORMATS[ images.Image(image_data).format ].lower()
  rescale_image_s3_key = gtools.ignore_special_charecter(user.username)+"_compressed_"+str(util.get_unique_key()) +"_"+ str(user.id) +".jpeg"
  rescale_image_s3_key = rescale_image_s3_key.replace(" ","")
  rescale_image_s3_key = boto_lib.save_img_in_s3(rescale_image, rescale_image_s3_key, s3_bucket=constants.USER_IMAGES_BUCKET)

  s3_short_image_key = gtools.ignore_special_charecter(user.username)+"_short_"+str(util.get_unique_key()) +"_"+ str(user.id) +".jpeg"
  s3_short_image_key = s3_short_image_key.replace(" ","")
  s3_short_image_key = boto_lib.save_img_in_s3(short_image, s3_short_image_key, s3_bucket=constants.USER_IMAGES_BUCKET)

  user.s3_compressed_image_key = rescale_image_s3_key
  user.s3_short_image_key = s3_short_image_key
  if session.is_modified(user):
    session.merge(user)
    session.commit()

  profile_image = boto_lib.get_image_url(s3_bucket=constants.USER_IMAGES_BUCKET, s3_key=user.s3_compressed_image_key)

  notification_for_update_settings(user, constants.UPDATE_USER_SETTINGS, profile_image, device_id = device_id)
  send_request_for_user_blur_image(user.id)
  return

def beta_users_validation(params):
  errors = {}

  if not params["user_name"]:
    errors["user_name"] = "Please enter your name."

  if not params["user_email"]:
    errors["user_email"] = "Please enter your email."
  else:
    if not util.validate_email(params['user_email']):
      errors["user_email"] = "Please enter a valid email."

  if not params["user_device"]:
    errors["user_device"] = "Please select device."
  else:
    if params["user_device"] not in [constants.IPHONE_DEVICE, constants.ANDROID_DEVICE]:
      errors["user_device"] = "Please select valid device."

  if not params["promise_text"]:
      errors["promise_text"] = "Please enter the promise here."
  else:
    if params["promise_text"].strip() != constants.PROMISE_TEXT:
      errors["promise_text"] = "Please give us right promise."

  if not params["invitee_details"]:
    errors["invitee_details"] = "Please enter valid friend's detail."
  return errors

def add_beta_users(params):
  response = {
    "status" : constants.ERROR,
    "errors" : None,
    "success" : None
  }
  errors = beta_users_validation(params)
  if errors:
    response["errors"] = errors
    return response
  
  beta_user = add_beta_user_object(params)
  logging.info("id %s and email %s for beta user : %s" % (str(beta_user.id), beta_user.email, beta_user.name))
  
  invitee_emails = [params["user_email"]]
  if params["invitee_details"]:
    invitee_emails = invitee_emails + [invitee_detail["email"].lower().strip() for invitee_detail in  params["invitee_details"]]
  
  existing_beta_invitees = get_existing_beta_invitees(invitee_emails)
  user_invitee_list = []

  if params["user_email"] not in existing_beta_invitees:
    user_invitee_list.append({
        "email" : params["user_email"],
        "name" : params["user_name"],
        "beta_user_id" : int(beta_user.id),
        "device_type" : constants.IPHONE_DEVICE if params["user_device"] == constants.IPHONE_DEVICE else constants.ANDROID_DEVICE,
        "is_launch_complete" : 0,
        "is_self_invitee" : 1,
        "added_date" : datetime.datetime.now()
      })

  if params["invitee_details"]:
    for invitee_detail in  params["invitee_details"]:
      device_type = gtools.int_or_none(invitee_detail["device_type"])
      if invitee_detail["email"] and invitee_detail["name"] and device_type:
        trimed_email = invitee_detail["email"].lower().strip()
        if trimed_email not in existing_beta_invitees:

          user_invitee_list.append({
            "email" : trimed_email,
            "name" : invitee_detail["name"],
            "beta_user_id" : int(beta_user.id),
            "device_type" : constants.ANDROID_DEVICE if device_type == constants.ANDROID_DEVICE else constants.IPHONE_DEVICE,
            "is_launch_complete" : 0,
            "is_self_invitee": 0,
            "added_date" : datetime.datetime.now()
          })

  if user_invitee_list:
    query = model.BetaUserInvitee.__table__.insert().values(user_invitee_list)
    session.execute(query)
    session.commit()
  
  invitee_emails = [invitee["email"] for invitee in user_invitee_list]
  if invitee_emails:
    comma_separated_emails = ",".join(invitee_emails)
    taskqueue.add(url='/tasks/update_already_signed_up_beta_users',
        method='GET',
        queue_name='optimize-queue',
        params={
              "emails" : comma_separated_emails,
            }
      )

  response["status"] = constants.SUCCESS
  response["data"] = {"msg":"Beta Users added successfully."}
  return response

def add_beta_user_object(params):
  beta_user = util.get_beta_user_by_email(params["user_email"])
  if beta_user:
    return beta_user

  beta_user = model.BetaUser()
  beta_user.email = params["user_email"]
  beta_user.name = params["user_name"]
  if params["user_device"] and params["user_device"] == constants.IPHONE_DEVICE:
    beta_user.device_type = constants.IPHONE_DEVICE
  else:
    beta_user.device_type = constants.ANDROID_DEVICE
  beta_user.added_date = datetime.datetime.now()
  session.add(beta_user)
  session.flush()
  session.commit()
  return beta_user

def get_existing_beta_invitees(emails):
  existing_emails = []
  if emails:
    beta_invitees = session.query(model.BetaUserInvitee).filter(model.BetaUserInvitee.email.in_(emails)).all()
    existing_emails = [beta_invitee.email for beta_invitee in beta_invitees]
  return existing_emails

def remind_users_to_upload_song():
  past48_time = datetime.datetime.now() - datetime.timedelta(hours=48)
  logging.info("start date :  %s"%str(past48_time))
  all_users = session.query(model.User.id, model.User.email, model.User.added_date).\
                                      filter(model.User.added_date < past48_time).\
                                      filter(model.User.upload_remind == True).\
                                      filter(model.User.signup_by == constants.WEB_SIGNUP).\
                                      filter(model.User.user_type == 0).all()
  
  for user in all_users:
    logging.info("Sending Remind Email : %s to became an artist "%user.email)
    taskqueue.add(url='/tasks/send_email_to_upload_a_song',
                method='POST',
                queue_name='email',
                params= { "email" : user.email}
                )
  return

def facebook_account_sync(user, facebook_token):
  response = {
    "status":constants.ERROR,
    "errors":None,
    "data":None,
  }
  try:
    graph = facebook.GraphAPI(facebook_token)
    response = graph.extend_access_token(constants.FACEBOOK_APP_ID, constants.FACEBOOK_APP_SECRET)
    if response.has_key("access_token") and response["access_token"]:
      facebook_token = response["access_token"]
    logging.info("Exchanged token ::   %s"%str(facebook_token))
    user = social_component.update_facebook_detail(user, facebook_token)
    response["status"] = constants.SUCCESS
    response["data"] = {"msg": "Facebook account synced successfully."}
  except Exception, e:
    logging.error(e)
    response['errors'] =  {"error":"Failed to fetch data from database."}
  logging.info("facebook sync response :: %s"%response)
  return response

def follow_up_email_to_launch_user_for_inviting_friends():
  today = datetime.datetime.now()
  yesterday = today - datetime.timedelta(hours=24)

  logging.info("current time : %s"%today)
  logging.info("time of past 24 hour from now : %s"%yesterday)
  users = session.query(model.User.id, model.User.email).filter(model.User.is_launch_complete == 0).\
                          filter(model.User.cluster_id != None).\
                          filter(model.User.is_active == 1).\
                          filter(model.User.is_followup_email_sent == 0).\
                          filter(model.User.added_date <= yesterday).\
                          all()
  for user in users:
    logging.info("Sending Remind Email : %s for inviting friends"%user.email)
    taskqueue.add(url='/tasks/send_email_to_launch_user_for_inviting_friends',
                method='POST',
                queue_name='email',
                params= { "user_id" : user.id}
                )
  return

def automated_email_to_artist_to_invite_friends():
  today = datetime.datetime.now()
  two_days_ago = today - datetime.timedelta(hours=48)

  logging.info("current time : %s"%today)
  logging.info("time of past 48 hour from now : %s"%two_days_ago)

  users = session.query(model.User.id, model.User.email).filter(model.User.user_type == 1).\
                          filter(model.User.is_active == 1).\
                          filter(model.User.is_automated_email_sent == 0).\
                          filter(model.User.added_date <= two_days_ago).\
                          all()

  emails_dict = {}
  emails = []

  for user in users:
    emails.append(user.email)
    emails_dict[user.email] = int(user.id)

  logging.info("all emails : %s"%emails)
  if not emails:
    return

  unsubscribes = session.query(model.UnsubscribeEmail.email).filter(model.UnsubscribeEmail.email.in_(emails)).all()
  unsubscribe_emails = [email.email for email in unsubscribes]
  logging.info("unsubscribed emails : %s"%unsubscribe_emails)

  emails = filter(lambda x:x not in unsubscribe_emails, emails)

  for email in emails:
    logging.info("Sending Automated Email : %s to invite friends"%email)
    taskqueue.add(url='/tasks/send_automated_email_to_artist_to_invite_friends',
                method='POST',
                queue_name='email',
                params= { "user_id" : emails_dict[email]}
                )
  return

def send_app_link_to_user_by_email(user):
  response = {
    "status":constants.ERROR,
    "errors":None,
    "data":None,
  }
  try:
    logging.info("Sending app link to : %s "%user.email)
    taskqueue.add(url='/tasks/send_app_link_to_user',
                method='POST',
                queue_name='email',
                params= { "user_id" : user.id}
                )
    response["status"] = constants.SUCCESS
    response["data"] = {"msg": "Link successfully sent to: " + user.email}
  except Exception, e:
    logging.error(e)
    response['errors'] =  {"error":"Failed to fetch data from database."}
  logging.info("facebook sync response :: %s"%response)
  return response

def is_valid_request_for_toggle(params):
  is_valid = False

  if params['playlist_id']:
    is_valid = True
  if params['playlist_name'] is not None:
    is_valid = True
  if params['add_playlist_toggle'] is not None:
    is_valid = True
  if params['is_rating_visited'] is not None:
    is_valid = True
  return is_valid

def update_user_playlist_toggle(user, params):
  response = {
    "status":constants.ERROR,
    "errors":None,
    "data":None,
  }
  try:
    logging.info(params)
    if not is_valid_request_for_toggle(params):
      response['errors'] = {"error": constants.INVALID_VALUE}
      return response

    playlist_id = user.playlist_id
    if params['is_rating_visited'] is not None:
      is_rating_visited = gtools.str_to_bool(params['is_rating_visited'])
    else:
      is_rating_visited = user.is_rating_visited

    if params['add_playlist_toggle'] is not None:
      add_playlist_toggle = gtools.str_to_bool(params['add_playlist_toggle'])
    else:
      add_playlist_toggle = user.add_playlist_toggle

    if params['playlist_id']:
      if not util.get_user_playlist(user, params['playlist_id']):
        response['errors'] = {"playlist_id": constants.INVALID_VALUE}
        return response

      if user.playlist_id:
        stmt = update(model.Playlist).where(model.Playlist.id==user.playlist_id).values(is_voting_playlist = False)
        result = session.execute(stmt)
        session.commit()

      stmt = update(model.Playlist).where(model.Playlist.id==params['playlist_id']).values(is_voting_playlist = True)
      result = session.execute(stmt)
      session.commit()
      playlist_id = params['playlist_id']

    elif params['playlist_name']:
      playlist = session.query( model.Playlist ).\
                              filter( model.Playlist.name == params['playlist_name']).\
                              filter( model.Playlist.user_id == user.id ).first()
      if playlist:
        response['errors'] = {"playlist_name": constants.ALREADY_EXISTS}
        return response

      playlist_id = playlist_component.create_playlist(params['playlist_name'], user, is_voting_playlist=True)

    is_modified = False
    if user.is_rating_visited != is_rating_visited:
      user.is_rating_visited = is_rating_visited
      is_modified = True

    if user.add_playlist_toggle != add_playlist_toggle:
      user.add_playlist_toggle = add_playlist_toggle
      is_modified = True

    if user.playlist_id != playlist_id:
      user.playlist_id = playlist_id
      is_modified = True

    if is_modified:
      session.merge(user)
      session.flush()
      session.commit()
   
    response["status"] = constants.SUCCESS
    response["data"] = {
      "msg" : "add playlist toggle updated successfully."
    }
  except Exception, e:
    logging.error(e)
    response['errors'] =  {"error":"Failed to fetch data from database."}
  logging.info("response :: %s"%response)
  return response

def save_user_invite_emails(user, emails):
  response = {
    "status" : constants.ERROR,
    "errors" : None,
    "data" : None
  }

  if not emails:
    response["erorrs"] = {"emails": constants.PARAM_REQUIRED}
    return response

  valid_emails = [email.strip() for email in emails.split(",") if util.validate_email(email.strip())]
  valid_emails = list(set(valid_emails))
  logging.info(valid_emails)

  if not valid_emails:
    response["erorrs"] = {"emails": constants.INVALID_VALUE}
    return response

  gae_session = gaesessions.get_current_session()
  gae_session["invite_emails"] = valid_emails
  gae_session.save()

  response["data"] = {"msg" : "Email saved successfully."}
  response["status"] = constants.SUCCESS
  return response
