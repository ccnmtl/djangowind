""" run tests for djangowind

$ virtualenv ve
$ ./ve/bin/pip install Django==1.7.6
$ ./ve/bin/pip install -r test_reqs.txt
$ ./ve/bin/python runtests.py
"""


import django
from django.conf import settings
from django.core.management import call_command


def main():
    # Dynamically configure the Django settings with the minimum necessary to
    # get Django running tests
    settings.configure(
        MIDDLEWARE_CLASSES=(
            'django.contrib.sessions.middleware.SessionMiddleware',
            'django.contrib.auth.middleware.AuthenticationMiddleware',
            'django.contrib.messages.middleware.MessageMiddleware',
        ),
        INSTALLED_APPS=(
            'django.contrib.sites',
            'django.contrib.auth',
            'django.contrib.contenttypes',
            'django.contrib.sessions',
            'djangowind',
            'django_jenkins',
        ),
        SITE_ID=1,
        JENKINS_TEST_RUNNER = 'django_jenkins.runner.CITestSuiteRunner',
        TEST_RUNNER='django.test.runner.DiscoverRunner',

        TEMPLATES=[
            {
                'BACKEND': 'django.template.backends.django.DjangoTemplates',
                'DIRS': [
                    # insert your TEMPLATE_DIRS here
                ],
                'APP_DIRS': True,
                'OPTIONS': {
                    'context_processors': [
                        'django.contrib.auth.context_processors.auth',
                        'django.template.context_processors.debug',
                        'django.template.context_processors.i18n',
                        'django.template.context_processors.media',
                        'django.template.context_processors.static',
                        'django.template.context_processors.tz',
                        'django.contrib.messages.context_processors.messages',
                    ],
                },
            },
        ],

        TEST_PROJECT_APPS = (
            'djangowind',
        ),
        COVERAGE_EXCLUDES_FOLDERS = ['migrations'],
        ROOT_URLCONF = 'djangowind.tests.urls',
        SOUTH_TESTS_MIGRATE=False,

        PROJECT_APPS = [
            'djangowind',
        ],
        # Django replaces this, but it still wants it. *shrugs*
        DATABASES = {
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': ':memory:',
                'HOST': '',
                'PORT': '',
                'USER': '',
                'PASSWORD': '',
            }
        },
    )

    try:
        # required by Django 1.7 and later
        django.setup()
    except AttributeError:
        pass

    # Fire off the tests
    call_command('jenkins')

if __name__ == '__main__':
    main()
