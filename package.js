/* global Package, Npm */
"use strict";

Package.describe({
    name: 'r00t3g:accounts-jira',
    version: '0.0.6',
    summary: 'Authenticate to a remote JIRA instance (forked from optilude:jira-auth)',
    git: 'https://github.com/r00t3g/meteor-jira-auth',
    documentation: 'README.md'
});

Npm.depends({
    "jira-connector": "1.2.1"
});

Package.onUse(function(api) {
    api.versionsFrom('1.2.0.1');

    api.use([
        'ecmascript',
        'oauth',
        'oauth1',
        'underscore',
        'service-configuration',
        'accounts-base',
        'accounts-oauth',
        'random'
    ]);

    api.imply([
        'accounts-base'
    ]);

    api.addFiles(['server.js'], 'server');
    api.addFiles(['client.js'], 'client');

    api.export('JiraAuth');
});
