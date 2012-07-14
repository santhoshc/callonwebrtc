#!/usr/bin/python2.4
# pylint: disable-msg=C6310

"""WebRTC Demo
"""

import datetime
import logging
import os
import random
import re
from google.appengine.api import channel
from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
from google.appengine.ext.webapp.util import run_wsgi_app

def generate_random(len):
  word = ''
  for i in range(len):
    word += random.choice('0123456789')
  return word

def sanitize(key):
  return re.sub("[^a-zA-Z0-9\-]", "-", key);

def make_token(room, user):
  return room.key().id_or_name() + '/' + user

def make_pc_config(stun_server):
  if stun_server:
    return "STUN " + stun_server
  else:
    return "STUN stun.l.google.com:19302"
    """return "STUN stun.counterpath.net"""
    

def insertDefaultUsers():
    q = db.GqlQuery("Select * from AllUsers")
    logging.info(q.count())
    if q.count() == 0:
        usera = AllUsers(key_name='santhosh')
        usera.username = 'santhosh'
        usera.password = 'santhosh'
        usera.status = 'Away'
        usera.put()
        
        userb = AllUsers(key_name='cherku')
        userb.username = 'cherku'
        userb.password = 'cherku'
        userb.status = 'Away'
        userb.put()


        userc = AllUsers(key_name='nalin')
        userc.username = 'nalin'
        userc.password = 'nalin'
        userc.status = 'Away'
        userc.put()
        
        userc = AllUsers(key_name='sam')
        userc.username = 'sam'
        userc.password = 'sam'
        userc.status = 'Away'
        userc.put()
        
        userc = AllUsers(key_name='adam')
        userc.username = 'adam'
        userc.password = 'adam'
        userc.status = 'Away'
        userc.put()
        
        userc = AllUsers(key_name='tom')
        userc.username = 'tom'
        userc.password = 'tom'
        userc.status = 'Away'
        userc.put()
        
        userc = AllUsers(key_name='venkatesh')
        userc.username = 'venkatesh'
        userc.password = 'venkatesh'
        userc.status = 'Away'
        userc.put()
        
        userc = AllUsers(key_name='june')
        userc.username = 'june'
        userc.password = 'june'
        userc.status = 'Away'
        userc.put()
        
        userc = AllUsers(key_name='nigel')
        userc.username = 'nigel'
        userc.password = 'nigel'
        userc.status = 'Away'
        userc.put()
        
        userc = AllUsers(key_name='yupui')
        userc.username = 'yupui'
        userc.password = 'yupui'
        userc.status = 'Away'
        userc.put()
        
        userc = AllUsers(key_name='brad')
        userc.username = 'brad'
        userc.password = 'brad'
        userc.status = 'Away'
        userc.put()
        
        userc = AllUsers(key_name='geoff')
        userc.username = 'geoff'
        userc.password = 'geoff'
        userc.status = 'Away'
        userc.put()
        
        userc = AllUsers(key_name='john')
        userc.username = 'john'
        userc.password = 'john'
        userc.status = 'Away'
        userc.put()
        
    cq = db.GqlQuery("Select * from ConfRoom")
    logging.info(q.count())
    if cq.count() == 0:
        croom1 = ConfRoom(key_name='101')
        croom1.room_key_name = '101'
        croom1.put() 
        
        croom2 = ConfRoom(key_name='202')
        croom2.room_key_name = '202'
        croom2.put()    
        




class AllUsers(db.Model):
    """All User Informations"""
    username = db.StringProperty()
    password = db.StringProperty()
    room_key = db.StringProperty()
    status = db.StringProperty()
    
    
class Room(db.Model):
  """All the data we store for a room"""
  room_owner = db.StringProperty()
  user1 = db.StringProperty()
  user1_room_key = db.StringProperty()
  url = db.StringProperty()
  status = db.StringProperty()

  def __str__(self):
    str = "["
    if self.room_owner:
      str += self.room_owner
    if self.user1:
      str += ", " + self.user1
    str += "]"
    return str

  def get_occupancy(self):
    occupancy = 0
    if self.room_owner:
      occupancy += 1
    if self.user1:
      occupancy += 1
    return occupancy

  def get_other_user(self, user):
    if user == self.user1:
      return self.room_owner
    elif user == self.room_owner:
      return self.user1
    else:
      return None

  def has_user(self, user):
    return (user and (user == self.user1 or user == self.room_owner))

  def add_owner(self, user):
    if not self.room_owner:
      self.room_owner = user
    else:
      raise RuntimeError('room already occupied')
    self.put()

  def add_user(self, user):
    if not self.user1:
      self.user1 = user
    else:
      raise RuntimeError('room is full')
    self.put()

  def remove_user(self, user):
    if user == self.user1:
      self.user1 = None
    if self.get_occupancy() > 0:
      self.put()
    else:
      self.delete()
  
  def remove_owner(self, user):
      self.delete()     


class ConfRoom(db.Model):
  """All the data we store for a room"""
  room_key_name = db.StringProperty()
  L =  db.StringListProperty()
  total_users = 0
  status = db.StringProperty()

  def __str__(self):
    str = self.room_key_name + " ["
    for user in self.L:
      str += ", " + user
    str += "]"
    return str

  def get_occupancy(self):
    return len(self.L)

  def get_other_user(self, user):
    retList = list()  
    for u in self.L:
        if u != user:
            retList.append(u)
    return retList

  def has_user(self, user):
    for u in self.L:
        if u == user:
            return True

  def add_user(self, user):
    if self.get_occupancy() < 4:
      self.L.append(user)
      self.total_users = self.total_users + 1
      self.put()
    else:
      raise RuntimeError('room is full')

  def remove_user(self, user):
    self.L.remove(user)
    self.total_users = self.total_users - 1
    self.put()
     


class ConnectPage(webapp.RequestHandler):
  def post(self):
    key = self.request.get('from')
    room_key, user = key.split('/');
    logging.info('User ' + user + ' connected to room ' + room_key)


class DisconnectPage(webapp.RequestHandler):
  def post(self):
    key = self.request.get('from')
    room_key, username = key.split('/');
    logging.info('Removing user ' + username + ' from room ' + room_key)
    room = Room.get_by_key_name(room_key)
    user = AllUsers.get_by_key_name(username)
    if room:
      other_user = room.get_other_user(username)
      if other_user:
        other_user_obj =AllUsers.get_by_key_name(other_user)  
        other_user_obj.status = 'Available'
        other_user_obj.put()
        
        other_room_key = room.user1_room_key
        other_room = Room.get_by_key_name(other_room_key)
        logging.info('Room ' + room_key + ' has state ' + str(room))
        room.user1 = None
        room.user1_room_key = None
        room.status = 'Available'
        room.put();
        
        other_room.user1 = None
        other_room.user1_room_key = None
        other_room.status = 'Available'
        other_room.put()
        channel.send_message(make_token(other_room, other_user), 'BYE')
        logging.info('Sent BYE to ' + other_user)
      
      room.delete()
        
      if user:
        user.status = 'Away'
        user.room_key = None
        user.put()
      else:
        logging.warning('Unknown user ' + username) 
    else:
      croom = ConfRoom.get_by_key_name(room_key)
      if croom:
          other_list = croom.get_other_user(user)
          for u in other_list:
              channel.send_message(make_token(croom, u), 'BYE->'+username)
          logging.info('Conf Room USER LIST--------------> ' + str(croom))
          croom.remove_user(username)
          logging.info('Conf Room USER LIST--------------> ' + str(croom))
          
      else:    
          logging.warning('Unknown room ' + room_key)
      
    
    

class HangUpPage(webapp.RequestHandler):
  def post(self):
    room_key = self.request.get('r')
    user = self.request.get('u')
    logging.info('Removing user ' + user + ' from room ' + room_key)
    room = Room.get_by_key_name(room_key)
    if room and room.has_user(user):
      cuser = AllUsers.get_by_key_name(user)
      other_user = room.get_other_user(user)
      if cuser:
        cuser.status = 'Available'
        cuser.put()
      if other_user:
        other_user_obj =AllUsers.get_by_key_name(other_user)  
        other_user_obj.status = 'Available'
        other_user_obj.put()
        
      other_room_key = room.user1_room_key
      other_room = Room.get_by_key_name(other_room_key)
      logging.info('Room ' + room_key + ' has state ' + str(room))
      if other_user:
        room.user1 = None
        room.user1_room_key = None
        room.status = 'Available'
        room.put();
        
        other_room.user1 = None
        other_room.user1_room_key = None
        other_room.status = 'Available'
        other_room.put()
        channel.send_message(make_token(other_room, other_user), 'BYE')
        logging.info('Sent BYE to ' + other_user)
    else:
      logging.warning('Unknown room ' + room_key)

class ConfHangUpPage(webapp.RequestHandler):
  def post(self):
    room_key = self.request.get('r')
    user = self.request.get('u')
    logging.info('Removing user ' + user + ' from room ' + room_key)
    croom = ConfRoom.get_by_key_name(room_key)
    if croom:
          other_list = croom.get_other_user(user)
          for u in other_list:
              channel.send_message(make_token(croom, u), 'BYE->'+user)
          croom.remove_user(user)
          logging.info('Conf Room USER LIST after hungup--------------> ' + str(croom))
    else:    
          logging.warning('Unknown room ' + room_key)

class MessagePage(webapp.RequestHandler):
  def post(self):
    message = self.request.body
    room_key = self.request.get('r')
    room = Room.get_by_key_name(room_key)
    if room:
      user = self.request.get('u')
      other_user = room.get_other_user(user)
      other_room_key = room.user1_room_key
      other_room = Room.get_by_key_name(other_room_key)
      if other_user:
        # special case the loopback scenario
        if other_user == user:
          message = message.replace("\"OFFER\"",
                                    "\"ANSWER\",\n   \"answererSessionId\" : \"1\"")
          message = message.replace("a=crypto:0 AES_CM_128_HMAC_SHA1_32",
                                    "a=xrypto:0 AES_CM_128_HMAC_SHA1_32")
        channel.send_message(make_token(other_room, other_user), message)
        logging.info('Delivered message to user ' + other_user);
    else:
      logging.warning('Unknown room ' + room_key)

class CMessagePage(webapp.RequestHandler):
  def post(self):
    message = self.request.body
    room_key = self.request.get('cr')
    remote_user = self.request.get('ru')
    room = ConfRoom.get_by_key_name(room_key)
    if room:
      user = self.request.get('u')
      other_list = room.get_other_user(user)
      for other_user in other_list:
        if other_user == remote_user:
            logging.info('Matched ---------------------------------->')
            message = message + 'USERID--->' + user
            channel.send_message(make_token(room, other_user), message)
            logging.info('Delivered message to user ' + other_user);
            break
    else:
      logging.warning('Unknown room ' + room_key)

class UsersPage(webapp.RequestHandler):
  def get(self):
    user = self.request.get('u')
    q = AllUsers.all()
    q = db.GqlQuery("SELECT * FROM AllUsers " +
                "WHERE username != :1 " ,
                user)
    user_list = q.fetch(100)
    htmls = '<table id="users"><tbody><tr><th>Buddies</th></tr>'
    flag = True
    for users in user_list:
        if users.status == 'Available':
            if flag:
                htmls+= '<tr><td  onclick="onCall(\''+users.username+'\',\''+users.room_key+'\')" ><img src="images/online.jpg" height="15" width="15" />&nbsp;&nbsp;&nbsp;'+users.username+'</td></tr>'
                flag = False
            else:
                htmls+= '<tr class="alt"><td onclick="onCall(\''+users.username+'\',\''+users.room_key+'\')" ><img src="images/online.jpg" height="15" width="15" />&nbsp;&nbsp;&nbsp;'+users.username+'</td></tr>'
                flag = True 
        elif users.status == 'Busy':
            if flag:
                htmls+= '<tr><td><img src="images/away.jpg" height="15" width="15" />&nbsp;&nbsp;&nbsp;'+users.username+'</td></tr>'
                flag = False
            else:
                htmls+= '<tr class="alt"><td><img src="images/away.jpg" height="15" width="15" />&nbsp;&nbsp;&nbsp;'+users.username+'</td></tr>'
                flag = True
        
        else:
            if flag:
                htmls+= '<tr><td><img src="images/offline.png" height="15" width="15" />&nbsp;&nbsp;&nbsp;'+users.username+'</td></tr>'
                flag = False
            else:
                htmls+= '<tr class="alt"><td><img src="images/offline.png" height="15" width="15" />&nbsp;&nbsp;&nbsp;'+users.username+'</td></tr>'
                flag = True         
    htmls+= '</tbody></table>'
    self.response.out.write(htmls)
    
    
class RoomAvailPage(webapp.RequestHandler):
  def get(self):
    remote_room_key = self.request.get('rr')
    remote_user = self.request.get('ru')
    user = self.request.get('u')
    room_key = self.request.get('r')
    room1 = Room.get_by_key_name(remote_room_key)
    room2 = Room.get_by_key_name(room_key)
    if room1 and room1.status == 'Available' and room2 and room2.status == 'Available':
        room1.add_user(user)
        room1.user1_room_key = room_key
        room1.status = 'Busy'
        room1.put()
        
        room2.add_user(remote_user);
        room2.user1_room_key = remote_room_key;
        room2.status = 'Busy'
        room2.put()
        
        cuser = AllUsers.get_by_key_name(user)
        cuser.status = 'Busy'
        cuser.put()
        
        ruser = AllUsers.get_by_key_name(remote_user)
        ruser.status = 'Busy'
        ruser.put()
        
        logging.warning( 'Room Available')
        self.response.out.write("Available")
        
    else:
      logging.warning( 'Room Busy')
      self.response.out.write("BUSY")

class LoginPage(webapp.RequestHandler):
    """The Login UI page, renders the 'login.html' template."""

    def post(self):
        """Renders the main page. When this page is shown, we create a new
        channel to push asynchronous updates to the client."""
        
        
        
        username = self.request.get('username');
        password = self.request.get('password')
        callType = self.request.get('calltype')
        debug = self.request.get('debug')
        stun_server = self.request.get('ss');
        bridge_id = self.request.get('bridgeid')
        
        q = db.GqlQuery("Select * from AllUsers where username =:1 and password = :2",username,password)
        logging.info(q.count())
        if q.count() > 0:
              logging.info(callType)
              if callType == 'conf':
                if bridge_id:
                    q = db.GqlQuery("Select * from ConfRoom where room_key_name =:1",bridge_id)
                    logging.info(q.count())
                    if q.count() == 0:
                        template_values = {'error':"Incorrect Bridge Id"}  
                        path = os.path.join(os.path.dirname(__file__), 'login.html')
                        self.response.out.write(template.render(path,template_values))
                        return
                    redirect = '/conf?username=' + username
                    if debug:
                        redirect += ('&debug=' + debug)
                    if stun_server:
                        redirect += ('&ss=' + stun_server)
                    if bridge_id:
                        redirect += ('&bridgeid=' + bridge_id)
                    self.redirect(redirect)
                    logging.info('Redirecting visitor to base URL to ' + redirect)
                    return
                else:
                    template_values = {'error':"Bridge Id should not be empty"}  
                    path = os.path.join(os.path.dirname(__file__), 'login.html')
                    self.response.out.write(template.render(path,template_values))
                    return 
                    
              userinfo = AllUsers.get_by_key_name(username)
              if userinfo.room_key:
                logging.info('deleting old room '+userinfo.room_key+' user '+userinfo.username)
                room = Room(key_name=userinfo.room_key)
                room.delete()
                userinfo.room_key=None
                userinfo.put();
              room_key = generate_random(8)
              redirect = '/?r=' + room_key
              if debug:
                redirect += ('&debug=' + debug)
              if stun_server:
                redirect += ('&ss=' + stun_server)
              redirect += ('&username=' + username)  
              self.redirect(redirect)
              logging.info('Redirecting visitor to base URL to ' + redirect)
              return
        else:
           template_values = {'error':"Incorrect Username or Password, Try Again"}  
           path = os.path.join(os.path.dirname(__file__), 'login.html')
           self.response.out.write(template.render(path,template_values))
           return 
        
    
class MainPage(webapp.RequestHandler):
  """The main UI page, renders the 'index.html' template."""

  def get(self):
    """Renders the main page. When this page is shown, we create a new
    channel to push asynchronous updates to the client."""
    
    logging.info('---------------------------------------------')
    insertDefaultUsers();
    logging.info('---------------------------------------------')
    
    username = self.request.get('username');
    room_key = sanitize(self.request.get('r'));
    debug = self.request.get('debug')
    stun_server = self.request.get('ss');
    
    if not room_key and not username:
      template_values = {}  
      path = os.path.join(os.path.dirname(__file__), 'login.html')
      self.response.out.write(template.render(path,template_values))
      return
      
    user = username
    initiator = 0
    room = Room.get_by_key_name(room_key)
    if not room:
      # New room.
      room = Room(key_name=room_key)
      room.room_owner = user
      room.url='https://callonwebrtc.appspot.com/?r=' + room_key
      room.status = 'Available'
      """room.url='http://localhost:8081?r=' + room_key"""
      room.put()
      
      userinfo = AllUsers.get_by_key_name(user)
      userinfo.status = "Available";
      userinfo.room_key = room_key;
      userinfo.put();
    else:
      template_values = {}  
      path = os.path.join(os.path.dirname(__file__), 'login.html')
      self.response.out.write(template.render(path,template_values))
      return  

    room_link = 'https://callonwebrtc.appspot.com/?r=' + room_key
    if stun_server:
      room_link += ('&ss=' + stun_server)

    token = channel.create_channel(room_key + '/' + user)
    pc_config = make_pc_config(stun_server)
    
    user_list = AllUsers.all();
    user_list.filter("username != ",user)
    results = user_list.fetch(100)

    for users in results:
        """logging.info( users.username +"," + users.room_key)"""
    
    
    
    template_values = {'token': token,
                       'me': user,
                       'room_key': room_key,
                       'room_link': room_link,
                       'initiator': initiator,
                       'pc_config': pc_config,
                       'results': results,
                       'username': username
                      }
    path = os.path.join(os.path.dirname(__file__), 'index.html')
    self.response.out.write(template.render(path, template_values))
    logging.info('User ' + user + ' added to room ' + room_key);
    logging.info('Room ' + room_key + ' has state ' + str(room))

class ConfPage(webapp.RequestHandler):
  """The main UI page, renders the 'index.html' template."""

  def get(self):
    """Renders the main page. When this page is shown, we create a new
    channel to push asynchronous updates to the client."""
    
    username = self.request.get('username');
    debug = self.request.get('debug')
    stun_server = self.request.get('ss');
    conf_room_key = sanitize(self.request.get('bridgeid'));
    
    if not conf_room_key:
        template_values = {'error':"Bridge Id should not be empty"}  
        path = os.path.join(os.path.dirname(__file__), 'login.html')
        self.response.out.write(template.render(path,template_values))
        return 
      
    user = username
    logging.info(conf_room_key)
    croom = ConfRoom.get_by_key_name(conf_room_key)
    
    q = db.GqlQuery("Select * from ConfRoom")
    conf_room_list = q.fetch(10)
    for rooms in conf_room_list:
        logging.info(str(rooms))
    
    logging.info(croom.get_occupancy())
    logging.info(croom.room_key_name)
        
    if croom.get_occupancy() == 0:
         initiator = 0
    else:
        initiator = 1
        
    if croom.get_occupancy() == 4:
          template_values = {'error':"Bridge is Full Please try Later"}  
          path = os.path.join(os.path.dirname(__file__), 'login.html')
          self.response.out.write(template.render(path,template_values))
          return 
    elif croom.has_user(user):
          template_values = {'error':user+" Already Logged in, Please close other sessions and try again"}  
          path = os.path.join(os.path.dirname(__file__), 'login.html')
          self.response.out.write(template.render(path,template_values))
          return 
    else:
          croom.add_user(user)  
           
    if stun_server:
      room_link += ('&ss=' + stun_server)

    logging.info('Conf Room USER LIST--------------> ' + str(croom))

    token = channel.create_channel(conf_room_key + '/' + user)
    pc_config = make_pc_config(stun_server)
    total_pc = croom.get_occupancy() - 1
    
    other_list = croom.get_other_user(user)
    user_list=''
    for u in other_list:
        user_list += u + ','

    template_values = {'token': token,
                       'total_pc': total_pc,
                       'user_list': user_list,
                       'me': user,
                       'room_key': conf_room_key,
                       'initiator': initiator,
                       'pc_config': pc_config,
                       'username': username
                      }
    path = os.path.join(os.path.dirname(__file__), 'index2.html')
    self.response.out.write(template.render(path, template_values))
    logging.info('User ' + user + ' added to conf room ' + conf_room_key);
    logging.info('Room ' + conf_room_key + ' has state ' + str(croom))


application = webapp.WSGIApplication([
    ('/', MainPage),
    ('/conf', ConfPage),
    ('/login', LoginPage),
    ('/message', MessagePage),
    ('/cmessage', CMessagePage),
    ('/checkAvailable', RoomAvailPage),
     ('/getUsers', UsersPage),
    ('/hangUP', HangUpPage),
    ('/confhangUP', ConfHangUpPage),
    ('/_ah/channel/connected/', ConnectPage),
    ('/_ah/channel/disconnected/', DisconnectPage)
  ], debug=True)


def main():
  run_wsgi_app(application)

if __name__ == "__main__":
  main()
