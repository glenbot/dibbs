import datetime

from flask import (
    redirect,
    url_for,
    session,
    request,
    render_template,
    g,
    abort,
    jsonify
)
from flask_oauth import OAuth, OAuthException

from app import app
from utils import login_required
from models import User, WarBase, Dibb

# init oauth
oauth = OAuth()


# start facebook
facebook = oauth.remote_app(
    'facebook',
    base_url='https://graph.facebook.com/',
    request_token_url=None,
    access_token_url='/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    consumer_key=app.config['FACEBOOK_APP_ID'],
    consumer_secret=app.config['FACEBOOK_APP_SECRET'],
    request_token_params={'scope': 'email'}
)


@app.context_processor
def context():
    return {
        'APP_NAME': app.config['APP_NAME'],
        'APP_TAGLINE': app.config['APP_TAGLINE']
    }


@app.before_request
def load_user():
    user = None
    if 'uid' in session:
        try:
            user = User.select().where(User.id == session['uid']).get()
        except User.DoesNotExist:
            pass

    g.user = user


@app.route('/')
@login_required
def index():
    ctx = {}
    today = datetime.datetime.now()

    ctx.update({
        'monday': (today - datetime.timedelta(days=today.weekday())).strftime("%B %d"),
        'war_bases': WarBase.select()
    })

    return render_template('index.html', **ctx)


@app.route('/set-handle', methods=['POST'])
@login_required
def set_handle():
    handle = request.form.get('handle', None)

    if not handle:
        resp = jsonify({'result': 'A handle was not given'})
        resp.status_code = 400
        return resp

    try:
        user = User.select().where(User.id == session['uid']).get()
    except User.DoesNotExist:
        abort(500)

    user.coc_handle = handle
    user.save()

    return 'ok'


@app.route('/dibb-base', methods=['POST'])
@login_required
def dibb_base():
    _id = request.form.get('id', None)

    if not _id:
        resp = jsonify({'result': 'An id was not given'})
        resp.status_code = 400
        return resp

    try:
        user = User.select().where(User.id == session['uid']).get()
        warbase = WarBase.select().where(WarBase.id == _id).get()
        dibbs = Dibb.select().where(Dibb.user == user)
    except (User.DoesNotExist, WarBase.DoesNotExist):
        abort(500)

    if warbase.dibbs.select().count() > 0:
        resp = jsonify({'result': 'Already claimed'})
        resp.status_code = 400
        return resp

    if dibbs.count() >= 2:
        resp = jsonify({'result': 'You can only dibb up to two bases. Either undibb or keep your current dibbs'})
        resp.status_code = 400
        return resp

    dibb = Dibb.create(user=user, warbase=warbase)
    dibb.save()

    return jsonify({'handle': user.coc_handle})


@app.route('/undibb-base', methods=['POST'])
@login_required
def undibb_base():
    _id = request.form.get('id', None)

    if not _id:
        resp = jsonify({'result': 'An id was not given'})
        resp.status_code = 400
        return resp

    try:
        user = User.select().where(User.id == session['uid']).get()
        warbase = WarBase.select().where(WarBase.id == _id).get()
        dibb = Dibb.select().where(Dibb.user == user, Dibb.warbase == warbase).get()
    except (User.DoesNotExist, WarBase.DoesNotExist, Dibb.DoesNotExist):
        abort(500)

    dibb.delete_instance()

    return jsonify({'handle': 'Available'})


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/login')
def login():
    ctx = {}
    return render_template('login.html', **ctx)


@app.route('/login-fb')
def login_facebook():
    return facebook.authorize(callback=url_for(
        'facebook_authorized',
        next=request.args.get('next') or request.referrer or None,
        _external=True
    ))


@app.route('/login/authorized')
@facebook.authorized_handler
def facebook_authorized(resp):
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    session['oauth_token'] = (resp['access_token'], '')

    # set the user context
    fb_user = facebook.get('/me')

    try:
        user = User.select().where(User.fb_id == fb_user.data['id']).get()
    except User.DoesNotExist:
        user = User.create(
            fb_id=fb_user.data['id'],
            name=fb_user.data['name'],
            email=fb_user.data['email'],
            coc_handle=None
        )
        user.save()

    session['uid'] = user.id

    return redirect(url_for('index'))


@facebook.tokengetter
def get_facebook_oauth_token():
    return session.get('oauth_token')
