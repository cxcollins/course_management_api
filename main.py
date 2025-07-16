from flask import Flask, request, jsonify, send_file
from google.cloud import datastore, storage
from google.api_core.exceptions import NotFound
import requests
from requests.exceptions import HTTPError
from six.moves.urllib.request import urlopen  # type: ignore
from jose import jwt
import json
from dotenv import load_dotenv
import os
import io

load_dotenv()

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

datastore_client = datastore.Client(project='project6-collicon')
storage_client = storage.Client()

DOMAIN = os.getenv('DOMAIN')
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
ALGORITHMS = ["RS256"]
REQUIRED_COURSE_FIELDS = ['subject', 'number', 'title', 'term', 'instructor_id']
BUCKET = 'collicon-project6-bucket'

USERS = 'Users'
COURSES = 'Courses'
ENROLLMENT = 'Enrollment'
ERROR_400 = 'The request body is invalid'
ERROR_403 = 'You don\'t have permission on this resource'
ERROR_404 = 'Not found'


def verify_jwt_return_sub(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                         "description":
                         "Authorization header is missing"}, 401)

    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload['sub']
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify({'Error': 'Unauthorized'})
    response.status_code = ex.status_code
    return response


# Get users
@app.route('/users', methods=['GET'])
def get_users():
    sub = verify_jwt_return_sub(request)

    query = datastore_client.query(kind=USERS)
    results = list(query.fetch())
    arr_to_return = []

    for r in results:
        r['id'] = r.id
        arr_to_return.append(r)
        if r['sub'] == sub:
            role = r['role']

    if role != 'admin':
        return jsonify({'Error': ERROR_403}), 403

    return arr_to_return, 200


# Get a user
@app.route('/users/<int:id>', methods=['GET'])
def get_user(id):
    sub = verify_jwt_return_sub(request)

    key = datastore_client.key(USERS, id)
    user = datastore_client.get(key=key)
    user['id'] = id

    if user['role'] != 'admin' and user['sub'] != sub:
        return jsonify({'Error': ERROR_403}), 403

    course_query = datastore_client.query(kind=COURSES)
    course_results = list(course_query.fetch())

    if user['role'] == 'student':
        courses = []
        for c in course_results:
            if user.key.id in c['enrollment']:
                courses.append(c)
        user['courses'] = courses

    elif user['role'] == 'instructor':
        courses = []
        for c in course_results:
            if user.key.id == c['instructor_id']:
                courses.append(c)
        user['courses'] = courses

    bucket = storage_client.get_bucket(BUCKET)
    blob = bucket.blob(str(id) + '/avatar.png')
    file_object = io.BytesIO()
    try:
        blob.download_to_file(file_object)
        file_object.seek(0)
    except NotFound:
        file_object = None

    url_root = request.url_root
    if file_object:
        avatar_url = url_root + 'users/' + str(id) + '/avatar'
        user['avatar_url'] = avatar_url

    return user, 200


# Upload avatar
@app.route('/users/<int:id>/avatar', methods=['POST'])
def upload_avatar(id):
    if 'file' not in request.files:
        return jsonify({'Error': ERROR_400}), 400

    sub = verify_jwt_return_sub(request)

    key = datastore_client.key(USERS, id)
    user = datastore_client.get(key=key)

    if user['sub'] != sub:
        return jsonify({'Error': ERROR_403}), 403

    file_obj = request.files['file']
    bucket = storage_client.get_bucket(BUCKET)
    blob = bucket.blob(str(id) + '/avatar.png')
    file_obj.seek(0)
    blob.upload_from_file(file_obj)

    url_root = request.url_root
    avatar_url = url_root + 'users/' + str(id) + '/avatar'

    return jsonify({'avatar_url': avatar_url}), 200


# Get avatar
@app.route('/users/<int:id>/avatar', methods=['GET'])
def get_avatar(id):
    sub = verify_jwt_return_sub(request)

    key = datastore_client.key(USERS, id)
    user = datastore_client.get(key=key)

    if user['sub'] != sub:
        return jsonify({'Error': ERROR_403}), 403

    bucket = storage_client.get_bucket('collicon-project6-bucket')
    try:
        blob = bucket.blob(str(id) + '/avatar.png')
        file_obj = io.BytesIO()
        blob.download_to_file(file_obj)
        file_obj.seek(0)
    except NotFound:
        return jsonify({'Error': ERROR_404}), 404

    return send_file(file_obj, mimetype='image/x-png', download_name='avatar.png')


# Delete an avatar
@app.route('/users/<int:id>/avatar', methods=['DELETE'])
def delete_avatar(id):
    sub = verify_jwt_return_sub(request)

    key = datastore_client.key(USERS, id)
    user = datastore_client.get(key=key)

    if user['sub'] != sub:
        return jsonify({'Error': ERROR_403}), 403

    bucket = storage_client.get_bucket(BUCKET)
    blob = bucket.blob(str(id) + '/avatar.png')

    try:
        blob.delete()
    except NotFound:
        return jsonify({'Error': ERROR_404}), 404

    return '', 204


# Login and get JWTs
@app.route('/users/login', methods=['POST'])
def login():
    content = request.get_json()
    try:
        username = content['username']
        password = content['password']
    except KeyError:
        return jsonify({'Error': 'The request body is invalid'}), 400

    body = {
        'grant_type': 'password',
        'username': username,
        'password': password,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'

    try:
        r = requests.post(url, json=body, headers=headers)
        r.raise_for_status()
        data = r.json()
    except HTTPError:
        return jsonify({'Error': 'Unauthorized'}), 401
    print(data)
    token = data['id_token']
    return {'token': token}, 200, {'Content-Type': 'application/json'}


# Create a course
@app.route('/courses', methods=['POST'])
def create_course():
    content = request.get_json()
    sub = verify_jwt_return_sub(request)

    query = datastore_client.query(kind=USERS)
    results = list(query.fetch())

    for r in results:
        if r['sub'] == sub:
            user = r
        if r.key.id == content['instructor_id']:
            instructor = r

    if user is None or instructor is None or user['role'] != 'admin':
        return jsonify({'Error': ERROR_403}), 403

    if (not content or instructor['role'] != 'instructor'
        or not all(field in content for field
                   in REQUIRED_COURSE_FIELDS)):
        return jsonify({'Error': ERROR_400}), 400

    new_course_key = datastore_client.key(COURSES)
    new_course = datastore.Entity(key=new_course_key)

    for field in content:
        new_course[field] = content[field]

    new_course['enrollment'] = []
    datastore_client.put(new_course)
    new_course['id'] = new_course.key.id

    url_root = request.url_root
    new_course['self'] = url_root + 'courses/' + str(new_course.key.id)

    return new_course, 201


# Get all courses
@app.route('/courses', methods=['GET'])
def get_courses():
    offset = request.args.get('offset', default=0, type=int)
    limit = request.args.get('limit', default=3, type=int)

    url_root = request.base_url

    query = datastore_client.query(kind=COURSES)
    query.order = ['subject']
    query_result = query.fetch(limit=limit, offset=offset)
    courses = list(query_result)

    for c in courses:
        c['id'] = c.key.id
        c['self'] = url_root + '/' + str(c.key.id)
        del c['enrollment']

    # TODO(): If I have time, input logic for if there should be another page
    next_url = (url_root + '?offset=' + str(offset + limit)
                + '&limit=' + str(limit))

    return jsonify({'courses': courses, 'next': next_url})


# Get a course
@app.route('/courses/<int:id>', methods=['GET'])
def get_course(id):
    key = datastore_client.key(COURSES, id)
    course = datastore_client.get(key)

    if not course:
        return jsonify({'Error': ERROR_404}), 404

    url_root = request.url_root
    course['self'] = url_root + 'courses/' + str(id)
    course['id'] = id

    del course['enrollment']

    return course, 200


# Update a course
@app.route('/courses/<int:id>', methods=['PATCH'])
def update_course(id):
    content = request.get_json()
    sub = verify_jwt_return_sub(request)
    base_url = request.base_url

    user, course = None, None

    user_query = datastore_client.query(kind=USERS)
    user_results = list(user_query.fetch())

    instructors_list = []
    for r in user_results:
        if r['sub'] == sub:
            user = r
        if r['role'] == 'instructor':
            instructors_list.append(r.key.id)

    if user is None or user['role'] != 'admin':
        return jsonify({'Error': ERROR_403}), 403

    course_query = datastore_client.query(kind=COURSES)
    course_results = list(course_query.fetch())

    for c in course_results:
        if c.key.id == id:
            course = c

    if not course:
        return jsonify({'Error': ERROR_403}), 403

    if content['instructor_id'] and content['instructor_id'] not in instructors_list:
        return jsonify({'Error': ERROR_400}), 400

    for field in content:
        course[field] = content[field]

    datastore_client.put(course)
    course['id'] = id
    course['self'] = base_url

    return course, 200


# Delete a course
@app.route('/courses/<int:id>', methods=['DELETE'])
def delete_course(id):
    sub = verify_jwt_return_sub(request)

    user_query = datastore_client.query(kind=USERS)
    user_results = list(user_query.fetch())

    user, course = None, None

    for r in user_results:
        if r['sub'] == sub:
            user = r

    if user is None or user['role'] != 'admin':
        return jsonify({'Error': ERROR_403}), 403

    course_query = datastore_client.query(kind=COURSES)
    course_results = list(course_query.fetch())

    for c in course_results:
        if c.key.id == id:
            course = c

    if not course:
        return jsonify({'Error': ERROR_403}), 403

    key = datastore_client.key(COURSES, c.key.id)
    datastore_client.delete(key)

    return '', 204


# Update enrollment
@app.route('/courses/<int:id>/students', methods=['PATCH'])
def update_enrollment(id):
    content = request.get_json()
    sub = verify_jwt_return_sub(request)
    user, course = None, None

    user_query = datastore_client.query(kind=USERS)
    user_results = list(user_query.fetch())
    user_ids = [user.key.id for user in user_results]

    for u in user_results:
        if u['sub'] == sub:
            user = u

    course_query = datastore_client.query(kind=COURSES)
    course_results = list(course_query.fetch())

    for c in course_results:
        if c.key.id == id:
            course = c

    if user is None or course is None or (user['role'] != 'admin'
            and user.key.id != course['instructor_id']):
        return jsonify({'Error': ERROR_403})

    if (set(content['add']) & set(content['remove'])
        or not all(uid in user_ids
                   for uid in content['add'] + content['remove'])):
        return jsonify({'Error': 'Enrollment data is invalid'}), 409

    # Add net new students to enrollment
    current_enrollment = course['enrollment']
    with_additions = set(current_enrollment).union(content['add'])
    after_removals = [student for student in with_additions
                      if student not in content['remove']]

    print(current_enrollment, with_additions, after_removals)
    course['enrollment'] = after_removals
    datastore_client.put(course)
    return '', 200


# Get enrollment
@app.route('/courses/<int:id>/students', methods=['GET'])
def get_enrollment(id):
    sub = verify_jwt_return_sub(request)
    user, course = None, None

    user_query = datastore_client.query(kind=USERS)
    user_results = list(user_query.fetch())

    for u in user_results:
        if u['sub'] == sub:
            user = u

    course_query = datastore_client.query(kind=COURSES)
    course_results = list(course_query.fetch())

    for c in course_results:
        if c.key.id == id:
            course = c

    if (user is None
            or course is None
            or (user['role'] != 'admin'
                and user.key.id != course['instructor_id'])):
        return jsonify({'Error': ERROR_403})

    return course['enrollment'], 200


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
