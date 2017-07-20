#!/usr/bin/env python
from setuptools import setup

setup(name='buildbot-webhook-gogs',
      version='0.1',
      description='Gogs web hook support for buildbot 9.9 and above',
      author='Joshua A Clayton',
      author_email='stillcompiling@gmail.com',
      url='https://github.com/d4ddi0/buildbot-webhook-gogs',
      license='GPLv2',
      packages=['buildbot_webhook_gogs',],
      entry_points={'buildbot.webhooks': 'gogs = buildbot_webhook_gogs:gogs'}
)

