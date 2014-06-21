import datetime

from flask import (
    redirect,
    url_for,
    session,
    request,
    render_template,
    g,
    abort,
    jsonify,
    flash
)
from flask_oauth import OAuth, OAuthException
from pbkdf2 import crypt

from app import app
from utils import login_required
from models import User, WarBase, Dibb
from utils import get_dictionary_from_model

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
        'APP_TAGLINE': app.config['APP_TAGLINE'],
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
        'war_bases': WarBase.select(),
        'users': list(User.select().where(User.coc_handle != None).order_by(User.coc_handle.asc()))
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

    handle = handle.strip()
    try:
        user = User.select().where(User.coc_handle == handle).get()
        resp = jsonify({'result': 'Handle has already been taken.'})
        resp.status_code = 400
        return resp
    except User.DoesNotExist:
        pass

    g.user.coc_handle = handle
    g.user.save()

    return 'ok'


@app.route('/dibb-base', methods=['POST'])
@login_required
def dibb_base():
    base_id = request.form.get('base_id', 0)

    if not base_id:
        resp = jsonify({'result': 'An id was not given'})
        resp.status_code = 400
        return resp

    try:
        warbase = WarBase.select().where(WarBase.id == base_id).get()
        dibbs = Dibb.select().where(Dibb.user == g.user)
    except (User.DoesNotExist, WarBase.DoesNotExist):
        abort(500)

    if warbase.dibbs.select().count() > 0:
        resp = jsonify({'result': 'Already dibbed'})
        resp.status_code = 400
        return resp

    if dibbs.count() >= 2:
        resp = jsonify({'result': 'You can only dibb up to two bases. Either undibb or keep your current dibbs'})
        resp.status_code = 400
        return resp

    dibb = Dibb.create(user=g.user, warbase=warbase)
    dibb.save()

    return jsonify({
        'warbase': get_dictionary_from_model(warbase),
        'dibb': get_dictionary_from_model(dibb),
        'user': get_dictionary_from_model(g.user, exclude={User: 'password'})
    })


@app.route('/dibb-for', methods=['POST'])
@login_required
def dibb_for():
    user_id = request.form.get('user_id', 0)
    base_id = request.form.get('base_id', 0)
    dibb_id = request.form.get('dibb_id', 0)
    static_user = request.form.get('static_user', None)

    if not base_id:
        resp = jsonify({'result': 'A base id was not given'})
        resp.status_code = 400
        return resp

    if not g.user.admin:
        resp = jsonify({'result': 'Not allowed to dibb for others'})
        resp.status_code = 400
        return resp

    if not static_user:
        static_user = None

    try:
        warbase = WarBase.select().where(WarBase.id == base_id).get()
    except WarBase.DoesNotExist:
        abort(500)

    user = None
    try:
        user = User.select().where(User.id == user_id).get()
    except User.DoesNotExist:
        pass
    except ValueError:  # users passed incorrectly
        pass

    dibb = None
    try:
        dibb = Dibb.select().where(Dibb.id == dibb_id).get()
    except Dibb.DoesNotExist:
        pass
    except ValueError:  # users passed incorrectly
        pass

    # setup a default return json
    return_json = {
        'warbase': get_dictionary_from_model(warbase),
        'user': get_dictionary_from_model(user, exclude={User: ['password']}),
        'dibb': get_dictionary_from_model(dibb)
    }

    if dibb is None:
        if user:
            dibb = Dibb.create(user=user, warbase=warbase)
            dibb.save()
            return_json.update({
                'dibb': get_dictionary_from_model(dibb)
            })
            return jsonify(return_json)

        if static_user:
            dibb = Dibb.create(user=g.user, warbase=warbase)
            dibb.static_user = static_user
            dibb.save()
            return_json.update({
                'user': get_dictionary_from_model(g.user, exclude={User: ['password']}),
                'dibb': get_dictionary_from_model(dibb)
            })
            return jsonify(return_json)
    else:
        if user:
            dibb.user = user
            dibb.save()
            return_json.update({
                'dibb': get_dictionary_from_model(dibb)
            })
            return jsonify(return_json)

        if static_user:
            dibb.user = g.user
            dibb.static_user = static_user
            dibb.save()
            return_json.update({
                'user': get_dictionary_from_model(g.user, exclude={User: ['password']}),
                'dibb': get_dictionary_from_model(dibb)
            })
            return jsonify(return_json)

    return jsonify(return_json)


@app.route('/undibb-base', methods=['POST'])
@login_required
def undibb_base():
    base_id = request.form.get('base_id', 0)

    if not base_id:
        resp = jsonify({'result': 'An id was not given'})
        resp.status_code = 400
        return resp

    dibb = None
    try:
        warbase = WarBase.select().where(WarBase.id == base_id).get()
        dibb = Dibb.select().where(Dibb.warbase == warbase).get()
    except WarBase.DoesNotExist:
        abort(500)
    except Dibb.DoesNotExist:
        resp = jsonify({'result': 'Base has not been dibbed yet'})
        resp.status_code = 400
        return resp

    if g.user.admin or g.user == dibb.user:
        dibb.delete_instance()
    else:
        resp = jsonify({'result': 'Not allowed to undibb base'})
        resp.status_code = 400
        return resp

    return jsonify({
        'warbase': get_dictionary_from_model(warbase),
        'dibb': get_dictionary_from_model(None),
        'user': get_dictionary_from_model(None)
    })


@app.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    ctx = {}
    if request.method == 'POST':
        username = request.form.get('username', None)
        password = request.form.get('password', None)
        honey_pot = request.form.get('xhp', None)

        # check for bots
        if honey_pot:
            return redirect('http://spam.abuse.net/overview/spambad.shtml')

        # update the context with a username
        ctx['username'] = username.strip()

        if not username or not password:
            msg = u'Please fill out the username and password fields.'
            flash(msg, 'danger')
        else:
            # check for existing username
            try:
                user = User.select().where(User.username == username.strip()).get()
                msg = u'Username has already been taken.'
                flash(msg, 'warning')
                return render_template('sign_up.html', **ctx)
            except User.DoesNotExist:
                pass

            encrypted_pw = crypt(password, iterations=100)
            user = User.create(
                username=username,
                password=encrypted_pw
            )
            user.save()

            # login the user
            session['uid'] = user.id

            msg = u'Successfully signed up. You have been auto-magically logged in.'
            flash(msg, 'success')

            return redirect(url_for('index'))

    return render_template('sign_up.html', **ctx)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/login')
def login():
    ctx = {}
    return render_template('login.html', **ctx)


@app.route('/login-standard', methods=['POST'])
def login_standard():
    username = request.form.get('username', None)
    password = request.form.get('password', None)
    honey_pot = request.form.get('xhp', None)

    # check for bots
    if honey_pot:
        return redirect('http://spam.abuse.net/overview/spambad.shtml')

    if username and password:
        username = username.strip()
        password = password.strip()

        try:
            user = User.select().where(User.username == username).get()
        except User.DoesNotExist:
            msg = u'Username was not found please sign up below.'
            flash(msg, 'warning')
            return redirect(url_for('sign_up'))

        if user.password == crypt(password, user.password):
            session['uid'] = user.id
            msg = u'Successfully logged in.'
            flash(msg, 'success')
            return redirect(url_for('index'))

        msg = u'Incorrect password'
        flash(msg, 'danger')
        return redirect(url_for('login'))

    msg = u'Please fill out the username and password fields'
    flash(msg, 'danger')
    return redirect(url_for('login'))


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
            coc_handle=None
        )
        user.save()

    session['uid'] = user.id

    return redirect(url_for('index'))


@facebook.tokengetter
def get_facebook_oauth_token():
    return session.get('oauth_token')
