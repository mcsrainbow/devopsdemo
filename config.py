import os
basedir = os.path.abspath(os.path.dirname(__file__))

CSRF_ENABLED = True
SECRET_KEY = 'devopsdemo_secret_key'

SQLALCHEMY_DATABASE_URI = 'mysql://demo_user:demo_pass@localhost/devopsdemo'
