#!/usr/bin/env python
from setuptools import setup

setup(name='buildbot-gogs',
      version='0.1',
      description='Gogs web hook support for buildbot 9.9 and above',
      author='Joshua Clayton',
      author_email='stillcompiling@gmail.com',
      packages=['buildbot_gogs',],
      entry_points={'buildbot.webhooks': 'gogs = buildbot_webhook_gogs:gogs'}
)

