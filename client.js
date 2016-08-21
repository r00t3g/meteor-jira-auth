/* global JiraAuth: true, OAuth, ServiceConfiguration, Random, Meteor, Accounts */
"use strict";

JiraAuth = {};

const serviceName = 'jira';

Accounts.oauth.registerService(serviceName);

Meteor.loginWithJira = function (options, callback) {

    if (!callback && typeof options === "function") {
        callback = options;
        options = null;
    }

    var credentialRequestCompleteCallback = Accounts.oauth.credentialRequestCompleteHandler(callback);
    JiraAuth.requestCredential(options, credentialRequestCompleteCallback);
};

JiraAuth.requestCredential = function (options, credentialRequestCompleteCallback) {

    if (!credentialRequestCompleteCallback && typeof options === 'function') {
        credentialRequestCompleteCallback = options;
        options = {};
    }

    let config = ServiceConfiguration.configurations.findOne({service: serviceName});

    if (!config) {
        if (credentialRequestCompleteCallback) {
            credentialRequestCompleteCallback(new ServiceConfiguration.ConfigError());
        }
        return;
    }

    let
        credentialToken = Random.secret(),
        loginStyle = OAuth._loginStyle(serviceName, config, options),
        stateParam = OAuth._stateParam(loginStyle, credentialToken),

        loginPath = [
            '_oauth/', serviceName, '/?requestTokenAndRedirect=true',
            '&state=', stateParam,
            '&jiraHost=', options.jiraHost,
            '&jiraPort=', options.jiraPort,
            '&jiraProtocol=', options.jiraProtocol
        ].join("");

    if (Meteor.isCordova) {
        loginPath = loginPath + "&cordova=true";
        if (/Android/i.test(navigator.userAgent)) {
            loginPath = loginPath + "&android=true";
        }
    }

    let loginUrl = Meteor.absoluteUrl(loginPath);

    OAuth.launchLogin(
        {
            loginService: serviceName,
            loginStyle: loginStyle,
            loginUrl: loginUrl,
            credentialRequestCompleteCallback: credentialRequestCompleteCallback,
            credentialToken: credentialToken
        }
    );
};
