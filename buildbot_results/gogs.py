from __future__ import absolute_import

from buildbot.process.properties import Properties
from buildbot.process.results import CANCELLED, EXCEPTION, FAILURE, RETRY, SKIPPED, SUCCESS, WARNINGS
from buildbot.reporters import http
from buildbot.util import httpclientservice
from re import search
from twisted.internet import defer
from twisted.python import log

class GogsCommentPush(http.HttpStatusPushBase):
    name = "GogsStatusPush"
    neededDetails = dict(wantProperties=True)

    def update_pull_request(self, build):
        codebase = next(i for i in build['buildset']['sourcestamps'] if i['codebase'] == 'evi')
        m = search('refs/pull/(\d+)/head', codebase['branch'])
        if not m:
            log.msg('{} is not a valid pull request'.format(codebase['branch']))
            return

        pull = m.group(1)
        url = '/api/v1/repos/uniwest/evi/issues/{}/comments'.format(pull)
        msg = 'build result: {}\n\n{}'.format(build['state_string'], build['url'])
        json = {'body': msg}

        return url, json

#    @defer.inlineCallbacks
#    def update_release(build)
#        pass

    @defer.inlineCallbacks
    def send(self, build):
        if not build['complete']:
            return

        props = Properties.fromDict(build['properties'])
        event = props['event']
        url = ''
        json = ''

        if event == 'pull_request':
            url, json = self.update_pull_request(build)
#        elif event == 'release':
#            url, json = self.update_release(build)
        else:
            log.msg('builder type {} not supported in GogsCommentPush()'.format(builder))
            return

        base_url = 'http://projects.columbia.uniwest.com:3000'
        auth = ('joshua', '2WideOpen')
        self._http = yield httpclientservice.HTTPClientService.getService(
                self.master, base_url, auth=auth, debug=True, headers={'Content-Type': 'application/json'}
                )
        response = yield self._http.post(url, json=json)
        if response.code != 200:
            log.msg('{}: unable to upload status: {} to {}'.format(response.code, response.content, url))
