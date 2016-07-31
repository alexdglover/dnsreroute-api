import os
from datetime import datetime
from urlparse import urlparse
from flask import Flask, request, flash, url_for, redirect, \
     render_template, abort, send_from_directory, jsonify, _request_ctx_stack
import jwt
import requests
import base64
from functools import wraps
from werkzeug.local import LocalProxy
from flask.ext.cors import CORS, cross_origin
import pymongo
from pymongo import MongoClient, IndexModel, ASCENDING, DESCENDING, errors
from bson.json_util import dumps
import json
from bson.objectid import ObjectId
import stripe

env = os.environ
client_id = os.environ['AUTH0_CLIENT_ID']
client_secret = os.environ["AUTH0_CLIENT_SECRET"]
stripe.api_key = os.environ["STRIPE_API_KEY"]

requestorEmail = ""

app = Flask(__name__)
app.config.from_pyfile('flaskapp.cfg')
CORS(app)

# Format error response and append status code.
def handle_error(error, status_code):
  resp = jsonify(error)
  resp.status_code = status_code
  return resp

def requires_auth(f):
  @wraps(f)
  def decorated(*args, **kwargs):
    auth = request.headers.get('Authorization', None)
    if not auth:
      return handle_error({'code': 'authorization_header_missing', 'description': 'Authorization header is expected'}, 401)

    parts = auth.split()

    if parts[0].lower() != 'bearer':
      return handle_error({'code': 'invalid_header', 'description': 'Authorization header must start with Bearer'}, 401)
    elif len(parts) == 1:
      return handle_error({'code': 'invalid_header', 'description': 'Token not found'}, 401)
    elif len(parts) > 2:
      return handle_error({'code': 'invalid_header', 'description': 'Authorization header must be Bearer + \s + token'}, 401)

    # This is the bearer token
    token = parts[1]

    try:
        payload = jwt.decode(
            token,
            base64.b64decode(client_secret.replace("_","/").replace("-","+")),
            audience=client_id
        )
    except jwt.ExpiredSignature:
        return handle_error({'code': 'token_expired', 'description': 'token is expired'}, 401)
    except jwt.InvalidAudienceError:
        return handle_error({'code': 'invalid_audience', 'description': 'incorrect audience, expected: ' + client_id}, 401)
    except jwt.DecodeError:
        return handle_error({'code': 'token_invalid_signature', 'description': 'token signature is invalid'}, 401)
    except Exception:
        return handle_error({'code': 'invalid_header', 'description':'Unable to parse authentication token.'}, 400)

    endpoint = "https://alexdglover.auth0.com/tokeninfo"
    headers = {"Authorization":"Bearer " + token}
    data = {"id_token": token}
    global requestorEmail
    try:
        requestorEmail = requests.post(endpoint,data=data,headers=headers).json()['email']
    except Exception as e:
        return handle_error({'code': 'failed_user_lookup', 'description': 'Unable to look up user with that token'})

    _request_ctx_stack.top.current_user = user = payload
    return f(*args, **kwargs)

  return decorated

def connect():
# Substitute the 5 pieces of information you got when creating
# the Mongo DB Database (underlined in red in the screenshots)
# Obviously, do not store your password as plaintext in practice
    connection = MongoClient(os.environ['OPENSHIFT_MONGODB_DB_URL'],int(os.environ['OPENSHIFT_MONGODB_DB_PORT']))
    handle = connection["dnsreroute"]
    handle.authenticate(os.environ['OPENSHIFT_MONGODB_DB_USERNAME'],os.environ['OPENSHIFT_MONGODB_DB_PASSWORD'])
    return handle

def initializeDb():
    handle.routes.create_index( [ ("incomingRoute", ASCENDING)], unique=True )
    handle.users.create_index( [ ("userEmail", ASCENDING)], unique=True )

handle = connect()

initializeDb()

# Sets response headers for all requests received. This is needed to allow
# pre-flight OPTIONS requests to get the information they need to do PUTs
# and DELETEs
@app.after_request
def after_request(response):
  response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin','*')
  #response.headers.add('Access-Control-Allow-Origin', '*')
  response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
  response.headers.add('Access-Control-Allow-Methods', 'PUT,POST,OPTIONS,DELETE,GET')
  return response

# Controllers API
@app.route("/")
def home():
    host = request.headers['Host']
    host = host.split(':')[0]
    if host != 'home.dnsreroute.xyz':
        route = handle.routes.find_one({'incomingRoute': host})
        if route:
            outgoingRoute = route['outgoingRoute']
            if route['type'] == "301":
                return redirect(outgoingRoute, 301)
            elif route['type'] == "302":
                return redirect(outgoingRoute)
            else:
                return '{"message": "Error - not able to determine redirect type"}'
        else:
            return '{"message": "Could not find a matching route"}', 404

    else:
      return "The Host header is {hostHeader}.This is the unsecured home page".format(hostHeader=request.headers['Host'])

@app.route("/ping",host="*")
def ping():
    return "All good. You don't need to be authenticated to call this"

@app.route("/secured/ping")
#@cross_origin(headers=['Access-Control-Allow-Origin', '*'])
@requires_auth
def securedPing():
    return "All good. You only get this message if you're authenticated"

###################################
###   Route URIs
###################################

@app.route("/routes/byUserEmail/<userEmail>", methods=['GET'])
@requires_auth
def getRoutesByUserEmail(userEmail):
    orgId = handle.users.find_one({"userEmail": userEmail})['orgId']
    print 'orgId is {orgId}'.format(orgId=orgId)
    routes = handle.routes.find({"orgId": ObjectId(orgId)})
    if routes:
        return dumps(routes)
    else:
        message = {"message": "No routes found with that orgId"}
        return jsonify(message), 404

@app.route("/routes/byOrg/<orgId>", methods=['GET'])
@requires_auth
def getRoutesByOrgId(orgId):
    orgId = validateObjectId(orgId)

    if not orgId:
        message = {"message": "Invalid org ID, uanble to convert to ObjectId. Must be a 12-byte input or a 24-character hex string"}
        return jsonify(message), 400

    routes = handle.routes.find({"orgId": orgId})
    if routes:
        return dumps(routes)
    else:
        message = {"message": "No routes found with that orgId"}
        return jsonify(message), 404


@app.route("/routes", methods=['POST'])
@requires_auth
def addRoute():
    if isAuthorized(requestorEmail, 'addRoute'):
        try:
            handle.routes.insert({"orgId": ObjectId(request.values['orgId']), "type": request.values['type'],
                "incomingRoute": request.values['incomingRoute'], "outgoingRoute": request.values['outgoingRoute']})
            return '{"message": "successfully added route"}'
        except pymongo.errors.DuplicateKeyError:
            errorDict = {"message": "Failed to add route - that incoming DNS name is already in use"}
            return jsonify(errorDict), 400
        except Exception as e:
            errorDict = {"message": "Failed to add route. Error message: {error}".format(error=e)}
            return jsonify(errorDict), 400
    else:
        # Not authorized
        errorDict = {"message": "You are not authorized to add another route!"}
        return jsonify(errorDict), 403

@app.route("/routes/<incomingRoute>", methods=['DELETE'])
@requires_auth
def deleteRoute(incomingRoute):
    # Validate incomingRoute is valid first
    route = handle.routes.find_one({"incomingRoute": incomingRoute})
    if route:
        if isAuthorized(requestorEmail, 'deleteRoute', incomingRoute):
            try:
                result = handle.routes.remove({"incomingRoute": incomingRoute})
                return '{"message": "Successfully deleted route"}'
            except Exception as e:
                errorDict = {"message": "Failed to delete route. Error message: {error}".format(error=e)}
                return jsonify(errorDict), 400
        else:
            # Not authorized
            errorDict = {"message": "You are not authorized to delete that route!"}
            return jsonify(errorDict), 403
    # If the route targeted for deletion wasn't found, return a 200 with explanation
    else:
        message = {"message": "Route doesn't exist, but that's OK! HTTP DELETE is an idempotent operation dude"}
        return jsonify(message)

###################################
###   End of Route URIs
###################################

###################################
###   User URIs
###################################

@app.route("/users")
@requires_auth
def getUsers():
    actor = handle.users.find_one({"userEmail": requestorEmail})
    users = handle.users.find({"orgId": ObjectId(actor['orgId'])})
    if users:
        return dumps(users)
    else:
        message = {"message": "No users found"}
        return jsonify(message), 404

@app.route("/users/byOrg/<orgId>")
@requires_auth
def getUsersByOrg(orgId):
    orgId = validateObjectId(orgId)

    if not orgId:
        message = {"message": "Invalid org ID, uanble to convert to ObjectId. Must be a 12-byte input or a 24-character hex string"}
        return jsonify(message), 400

    users = handle.users.find({"orgId": orgId})
    if users:
        return dumps(users)
    else:
        message = {"message": "No users found with that org ID"}
        return jsonify(message), 404

@app.route("/users/<userEmail>", methods=['GET'])
@requires_auth
def getUserByEmail(userEmail):
    user = handle.users.find_one({"userEmail": userEmail})
    if user:
        user['_id'] = str(user['_id'])
        user['orgId'] = str(user['orgId'])
        return dumps(user)
    else:
        message = {"message": "No user found with that email address"}
        return jsonify(message), 404

@app.route("/users/<userEmail>", methods=['PUT'])
@requires_auth
def updateUser(userEmail):
    if requestorEmail == userEmail:
        user = handle.users.find_one({"userEmail": userEmail})
        if user:
            result = handle.users.update_one( { "userEmail": userEmail },
                {
                  "$set": {
                    # "userEmail": userEmail,
                    "userName": request.values['userName'],
                    "orgId": ObjectId(request.values['orgId'])
                  }
                }
            )
            message = {"message": "User updated successfully"}
            return jsonify(message)
        else:
            message = {"message": "No user found with that email address"}
            return jsonify(message), 404
    else:
        message = {"message": "You are not authorized to update that user. You may only update your own user information"}
        return jsonify(message), 403

@app.route("/users", methods=['POST'])
@requires_auth
def addUser():
    if isAuthorized(requestorEmail, 'addUser', request.values['orgId']):
        try:
            handle.users.insert({"userEmail":request.values['userEmail'], "userName":request.values['userName'], "orgId": ObjectId(request.values['orgId']) })
            message = {"message": "Successfully added user"}
            return jsonify(message)
        except pymongo.errors.DuplicateKeyError:
            errorDict = {"message": "User with that email already exists"}
            return jsonify(errorDict), 409
        except Exception as e:
            errorDict = {"message": "Failed to add user. Error message: {error}".format(error=e)}
            return jsonify(errorDict), 400
    else:
        # Not authorized
        errorDict = {"message": "You are not authorized to add another user!"}
        return jsonify(errorDict), 403

@app.route("/users/register", methods=['POST'])
@requires_auth
def registerNewUser():
    try:
        orgId = handle.orgs.insert({"orgName": request.values['userEmail'], "subscription": "freeTier"})
        handle.users.insert({"userEmail":request.values['userEmail'], "userName":request.values['userName'], "orgId": ObjectId(orgId) })
        message = {"message": "Successfully registered user"}
        return jsonify(message)
    except pymongo.errors.DuplicateKeyError:
        errorDict = {"message": "User with that email already exists"}
        return jsonify(errorDict), 409
    except Exception as e:
        errorDict = {"message": "Failed to add user. Error message: {error}".format(error=e)}
        return jsonify(errorDict), 400

@app.route("/users/<userEmail>", methods=['DELETE'])
@requires_auth
def deleteUser(userEmail):
    targetUser = handle.users.find_one({"userEmail": userEmail})
    if targetUser:
        if isAuthorized(requestorEmail, 'deleteUser', userEmail):
            try:
                result = handle.users.remove({"userEmail": userEmail})
                message = {"message": "Successfully deleted user"}
                return jsonify(message)
            except Exception as e:
                errorDict = {"message": "Failed to delete user. Error message: {error}".format(error=e)}
                return jsonify(errorDict), 400
        else:
            # Not authorized
            errorDict = {"message": "You are not authorized to delete that user!"}
            return jsonify(errorDict), 403
    # If the user targeted for deletion wasn't found, return a 200 with explanation
    else:
        message = {"message": "User doesn't exist, but that's OK! HTTP DELETE is an idempotent operation dude"}
        return jsonify(message)

###################################
###   End of User URIs
###################################

###################################
###   Org URIs
###################################
@app.route("/orgs", methods=['POST'])
@requires_auth
def addOrg():
    try:
        orgId = handle.orgs.insert({"orgName": request.values['userEmail'], "subscription": "freeTier"})
        return '{"message": "Successfully added org"}'
    except pymongo.errors.DuplicateKeyError:
        errorDict = {"message": "Org already exists"}
        return jsonify(errorDict), 400
    except Exception as e:
        errorDict = {"message": "Failed to add org. Error message: {error}".format(error=e)}
        return jsonify(errorDict), 400

@app.route("/orgs/<orgId>", methods=['PUT'])
@requires_auth
def updateOrg(orgId):
    orgId = validateObjectId(orgId)

    if not orgId:
        message = {"message": "Invalid org ID, uanble to convert to ObjectId. Must be a 12-byte input or a 24-character hex string"}
        return jsonify(message), 400

    try:
        org = handle.orgs.find_one( {"_id": orgId} )

        if org:
            result = handle.orgs.update_one( {"_id": orgId},
                {
                  "$set": {
                    "orgName": request.values['orgName']
                  }
                }
            )
            message = {"message": "Org updated successfully"}
            return jsonify(message)
        else:
            message = {"message": "No org with that id"}
            return jsonify(message), 404
    except Exception as e:
        errorDict = {"message": "Failed to update org. Error message: {error}".format(error=e)}
        return jsonify(errorDict), 400

@app.route("/orgs/<orgId>", methods=['GET'])
@requires_auth
def getOrg(orgId):
    orgId = validateObjectId(orgId)

    if not orgId:
        message = {"message": "Invalid org ID, uanble to convert to ObjectId. Must be a 12-byte input or a 24-character hex string"}
        return jsonify(message), 400

    org = handle.orgs.find_one({"_id": orgId})
    if org:
        org['_id'] = str(org['_id'])
        return dumps(org)
    else:
        message = {"message": "No org found with that orgId"}
        return jsonify(message), 404

@app.route("/orgs/<orgId>", methods=['DELETE'])
@requires_auth
def deleteOrg(orgId):
    orgId = validateObjectId(orgId)

    if not orgId:
        message = {"message": "Invalid org ID, uanble to convert to ObjectId. Must be a 12-byte input or a 24-character hex string"}
        return jsonify(message), 400

    org = handle.orgs.find_one({"_id": orgId})

    if isAuthorized(requestorEmail, 'deleteOrg', orgId):
        # Cancel Stripe subscription
        if 'subscriptionId' in org:
            try:
                subscriptionId = org['subscriptionId']
                subscription = stripe.Subscription.retrieve(subscriptionId)
                subscription.delete()
            except Exception as e:
                errorDict = {"message": "Error occurred while updating existing subscription. Error message: {error}".format(error=e)}
                return jsonify(errorDict), 400

        # Delete all associated user accounts
        handle.users.remove({"orgId": orgId})

        # Delete all associated routes
        handle.routes.remove({"orgId": orgId})

        try:
            result = handle.orgs.remove({"_id": orgId})
            return '{"message": "Successfully deleted org"}'
        except Exception as e:
            errorDict = {"message": "Failed to delete org. Error message: {error}".format(error=e)}
            return jsonify(errorDict), 400
    else:
        # Not authorized
        errorDict = {"message": "You are not authorized to delete that org!"}
        return jsonify(errorDict), 403


@app.route("/orgs/<orgId>/subscription", methods=['PUT'])
@requires_auth
def addSubscriptionToOrg(orgId):
    orgId = validateObjectId(orgId)

    if not orgId:
        message = {"message": "Invalid org ID, uanble to convert to ObjectId. Must be a 12-byte input or a 24-character hex string"}
        return jsonify(message), 400

    # Check org for existing customer ID
    try:
        org = handle.orgs.find_one( {"_id": orgId} )
        if org:
            print "org is:"
            print org
            if 'subscriptionId' in org:
                try:
                    subscriptionId = org['subscriptionId']
                    subscription = stripe.Subscription.retrieve(subscriptionId)
                    subscription.plan = request.values['subscription']
                    subscription.save()
                except Exception as e:
                    errorDict = {"message": "Error occurred while updating existing subscription. Error message: {error}".format(error=e)}
                    return jsonify(errorDict), 400

                result = handle.orgs.update_one( {"_id": orgId},
                    {
                      "$set": {
                        "subscription": request.values['subscription']
                      }
                    }
                )
                message = {"message": "Org updated with subscription successfully"}
                return jsonify(message)
            else:
                try:
                    stripeCustomer = stripe.Customer.create(
                      source=request.values['tokenId'], # obtained from Stripe.js
                      plan=request.values['subscription'],
                      email=request.values['userEmail']
                    )
                    print "stripeCustomer is:"
                    print stripeCustomer
                    subscriptionId = stripeCustomer.subscriptions.data[0].id
                except Exception as e:
                    errorDict = {"message": "Error occurred while creating new user and subscription. Error message: {error}".format(error=e)}
                    return jsonify(errorDict), 400
                result = handle.orgs.update_one( {"_id": orgId},
                    {
                      "$set": {
                        "subscription": request.values['subscription'],
                        "subscriptionId": subscriptionId
                      }
                    }
                )
                message = {"message": "Org updated with subscription successfully"}
                return jsonify(message)
        else:
            message = {"message": "No org with that id"}
            return jsonify(message), 404
    except Exception as e:
        errorDict = {"message": "Failed to update org. Error message: {error}".format(error=e)}
        return jsonify(errorDict), 400

###################################
###   End of Org URIs
###################################



###################################
###   Subscription URIs
###################################

@app.route("/subscriptions/<subscriptionName>", methods=['GET'])
@requires_auth
def getSubscription(subscriptionName):
    subscription = handle.subscriptions.find_one({"subscriptionName": subscriptionName})
    if subscription:
        subscription['_id'] = str(subscription['_id'])
        return dumps(subscription)
    else:
        message = {"message": "No subscription found with that subscriptionName"}
        return jsonify(message), 404

###################################
###   End of Subscription URIs
###################################

###################################
###   Non-URI Functions
###################################

def validateObjectId(objectId):
    try:
        objectId = ObjectId(objectId)
        return objectId
    except:
        return None

def isAuthorized(actorEmail, action, target=None):
    actor = handle.users.find_one({"userEmail": actorEmail})
    org = handle.orgs.find_one({"_id": ObjectId(actor['orgId'])})
    print org
    maxRoutes = { 'freeTier': 1, 'developerTier': 10, 'enterpriseTier': 100 }
    if action == 'addUser':
        if (org['subscription'] == 'developerTier') or (org['subscription'] == 'enterpriseTier'):
            print 'Subscription is not freeTier, requesting user is authorized to add that user. Checking target org'
            if ObjectId(target) == actor['orgId']:
                print 'Target org matches requesting users org, request is authorized'
                return True
            else:
                return True
        else:
            print 'Subscription is freeTier or some unhandled value, requesting user is NOT authorized to add target user'
            return False

    elif action == 'deleteUser':
        targetUser = handle.users.find_one({"userEmail": target})
        if (org['subscription'] == 'developerTier') or (org['subscription'] == 'enterpriseTier'):
            if actorEmail != target:
                if actor['orgId'] == targetUser['orgId']:
                    print 'Subscription is not freeTier, the user is not deleting themself, and this user is part of the same org. Requesting user is authorized to delete target user'
                    return True
                else:
                    print 'Subscription is not freeTier, the user is not deleting themself, but the user is NOT part of the same org. Requesting user is NOT authorized to delete target user'
                    return False
            else:
                print 'Subscription is not freeTier, but the user is attempting to delete themself. Requesting user is NOT authorized to delete target user'
                return False
        else:
            print 'Subscription is freeTier or some unhandled value, requesting user is NOT authorized to delete target user'
            return False

    elif action == 'addRoute':
        routeCount = handle.routes.find({"orgId": org['_id']}).count()
        if routeCount < maxRoutes[org['subscription']]:
            print 'Current routeCount is less than maxRoutes, requesting user is authorized to create target route'
            return True
        else:
            print 'Current routeCount is equal to or greater than maxRoutes, requesting user is NOT authorized to create target route'
            return False
    elif action == 'deleteRoute':
        targetRoute = handle.routes.find_one({"incomingRoute": target})
        if org['_id'] == targetRoute['orgId']:
            print 'User is trying to delete a route that is owned by their org, requesting user is authorized to delete target route'
            return True
        else:
            print 'User is trying to delete a route that is NOT owned by their org, requesting user is NOT authorized to delete target route'
            return False
    elif action == 'deleteOrg':
        targetOrg = handle.orgs.find_one({"incomingRoute": target})
        if org['_id'] == targetOrg['_id']:
            print 'User is trying to delete their own org, requesting user is authorized to delete target org'
            return True
        else:
            print 'User is trying to delete some other org, requesting user is NOT authorized to delete target org'
            return False
    else:
        print 'Unable to determine action, requesting user is NOT authorized'
        return False


###################################
###   End of Non-URI Functions
###################################


if __name__ == '__main__':
    app.run(app.config['IP'], app.config['PORT'])
