# This file is part of Buildbot.  Buildbot is free software: you can
# redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation, version 2.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright Buildbot Team Members

from __future__ import absolute_import
from __future__ import print_function

import hmac
import json
import logging
import re
from hashlib import sha1

from dateutil.parser import parse as dateparse
from subprocess import check_output
from twisted.python import log

from buildbot.util import bytes2NativeString
from buildbot.util import unicode2bytes
from buildbot.www.hooks.base import BaseHookHandler
from time import sleep

_HEADER_CT = b'Content-Type'
_HEADER_EVENT = b'X-Gogs-Event'
_HEADER_SIGNATURE = b'X-Gogs-Signature'


class GogsEventHandler(object):
    def __init__(self, secret, strict, codebase=None):
        self._secret = secret
        self._strict = strict
        self._codebase = codebase

        if self._strict and not self._secret:
            raise ValueError('Strict mode is requested '
                             'while no secret is provided')

    def process(self, request):
        payload = self._get_payload(request)

        event_type = request.getHeader(_HEADER_EVENT)
        event_type = bytes2NativeString(event_type)
        log.msg("X-Gogs-Event: {}".format(

            event_type), logLevel=logging.DEBUG)

        handler = getattr(self, 'handle_{}'.format(event_type), None)

        if handler is None:
            raise ValueError('Unknown event: {}'.format(event_type))

        return handler(payload, event_type)

    def _get_payload(self, request):
        content = request.content.read()
        content = bytes2NativeString(content)

        signature = request.getHeader(_HEADER_SIGNATURE)
        signature = bytes2NativeString(signature)

        if not signature and self._strict:
            raise ValueError('Request has no required signature')

        if self._secret and signature:
            try:
                hash_type, hexdigest = signature.split('=')
            except ValueError:
                log.msg("X-Gogs-Signature: {}".format(signature))
                raise ValueError(
                    'Wrong signature format: {}'.format(signature))

            if hash_type != 'sha1':
                raise ValueError('Unknown hash type: {}'.format(hash_type))

            mac = hmac.new(unicode2bytes(self._secret),
                           msg=unicode2bytes(content),
                           digestmod=sha1)
            # NOTE: hmac.compare_digest should be used, but it's only available
            # starting Python 2.7.7
            if mac.hexdigest() != hexdigest:
                raise ValueError('Hash mismatch')

        content_type = request.getHeader(_HEADER_CT)
        content_type = bytes2NativeString(content_type)

        if content_type == 'application/json':
            payload = json.loads(content)
        elif content_type == 'application/x-www-form-urlencoded':
            payload = json.loads(request.args['payload'][0])
        else:
            raise ValueError('Unknown content type: {}'.format(content_type))

        log.msg("Payload: {}".format(payload), logLevel=logging.DEBUG)

        return payload

    def get_codebase(self, payload):
        if callable(self._codebase):
            return self._codebase(payload)
        elif self._codebase is not None:
           return self._codebase
        else:
            return None

    def handle_ping(self, _, __):
        return []

    def handle_create(self, payload, event):
        change = {
            'codebase': self.get_codebase(payload),
            'project': payload['repository']['full_name'],
            'branch': payload['ref'],
            'repository': payload['repository']['clone_url'],
            'properties': {
                'event': event,
                'ref_type': payload['ref_type'],
            },
            'author': u'{} <{}>'.format(payload['sender']['full_name'],
                                       payload['sender']['email']),
            'files': [],
            'comments': 'Created new {} called {}'.format(payload['ref_type'],
                                                          payload['ref']),
            'revision': payload['ref'],
            'when_timestamp': dateparse(payload['repository']['updated_at']),
            'revlink': '{}/src/{}'.format(payload['repository']['html_url'], payload['ref']),
        }

        return [change,]

    def handle_push(self, payload, event):
        project = payload['repository']['full_name']

        # We only care about regular heads or tags
        match = re.match(r"^refs/(heads|tags)/(.+)$", payload['ref'])
        if not match:
            log.msg("Ignoring refname `{}': Not a branch".format(refname))
            return []

        branch = match.group(2)
        if payload.get('deleted'):
            log.msg("Branch `{}' deleted, ignoring".format(branch))
            return []

        change_base = {
            'codebase': self.get_codebase(payload),
            'project': project,
            'branch': branch,
            'repository': payload['repository']['clone_url'],
            'properties': {
                'event': event
            },
        }
        changes = []
        for commit in payload['commits']:
            log.msg("New revision: {}".format(commit['id'][:8]))

            change = change_base.copy()
            change.update(self.get_commit(commit))
            changes.append(change)

        log.msg("Received {} changes from {}".format(len(changes), project))

        return changes

    def get_commit(self, commit):
        files = []
        for kind in ('added', 'modified', 'removed'):
            files.extend(commit.get(kind, []))

        change = {
            'author': u'{} <{}>'.format(commit['author']['name'],
                                       commit['author']['email']),
            'files': files,
            'comments': commit['message'],
            'revision': commit['id'],
            'when_timestamp': dateparse(commit['timestamp']),
            'revlink': commit['url'],
        }

        return change

    def handle_release(self, payload, event):

        repo_url = payload['repository']['html_url']
        release = payload['release']['tag_name']
        project = payload['repository']['full_name']
        title = u'{} [{} release {}]'.format(payload['release']['name'],
                                            project, release)
        comment = payload['release']['body']
        change = {
            'author': u'{} <{}>'.format(payload['release']['author']['full_name'],
                                       payload['release']['author']['email']),
            'branch': release,
            'category': 'release',
            'comments': u'{}\n{}'.format(title, comment),
            'revision': release,
            'when_timestamp': dateparse(payload['release']['created_at']),
            'repository': payload['repository']['clone_url'],
            'project': project,
            'properties': {
                'action': payload['action'],
                'draft': payload['release']['draft'],
                'prerelease': payload['release']['prerelease'],
                'event': event,
            },
            'revlink': u'{}/src/{}'.format(repo_url, release),
        }

        return [change,]

    def get_pull_request_rev(self, repo, refname):
        sleep(0.1)
        return check_output(['git', 'ls-remote', repo, refname]).split()[0]

    def handle_pull_request(self, payload, event):
        repo_url = payload['repository']['html_url']
        number = payload['number']
        refname = 'refs/pull/{}/head'.format(number)
        title = payload['pull_request']['title']
        comments = payload['pull_request']['body']
        project = payload['pull_request']['base_repo']['full_name']
        repo = payload['pull_request']['base_repo']['clone_url']

        log.msg('Processing Gogs Pull Request #{}'.format(number),
                logLevel=logging.DEBUG)

        action = payload.get('action')
        if action not in ('opened', 'reopened', 'synchronized'):
            log.msg("Gogs Pull Request #{} {}, ignoring".format(number, action))
            return []

        properties = {}
#        properties = self.extractProperties(payload['pull_request'])
        properties.update({'event': event})
        log.msg("properties... " + repr(properties))

        change = {
            'codebase': self.get_codebase(payload),
            'revision': self.get_pull_request_rev(repo, refname),
            'when_timestamp': dateparse(payload['pull_request']['head_repo']['updated_at']),#not quite right
            'branch': refname,
            'revlink': u'{}/pulls/{}'.format(repo_url, number),
            'repository': repo,
            'project': project,
            'category': 'pull',
            'author': u'{} <{}>'.format(payload['pull_request']['user']['full_name'],
                                        payload['pull_request']['user']['email']),
            'comments': '{} [{} PR#{}]\n{}'.format(title, project, number, comments),
            'properties': properties,
        }

        log.msg("Received Gogs Pull Request #{}".format(number))
        return [change,]


class GogsHandler(BaseHookHandler):
    def __init__(self, master, options = {}):
        BaseHookHandler.__init__(self, master, options)
        handler_class = options.get('class', GogsEventHandler)
        if not issubclass(handler_class, GogsEventHandler):
            msg = '{} is not a subclass of GogsEventHandler'
            raise ValueError(msg.format(handler_class))

        self.handler = handler_class(options.get('secret', None),
                                     options.get('strict', False),
                                     options.get('codebase', None))

    def getChanges(self, request):
        return self.handler.process(request), 'git'

gogs = GogsHandler
