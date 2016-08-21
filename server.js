/* global OAuth, ServiceConfiguration, Meteor, HTTP, _, Accounts, Npm, Random */
"use strict";

const JiraClient = Npm.require('jira-connector');
const getAuthorizeURL = Meteor.wrapAsync(JiraClient.oauth_util.getAuthorizeURL, JiraClient.oauth_util);
const swapRequestTokenWithAccessToken = Meteor.wrapAsync(JiraClient.oauth_util.swapRequestTokenWithAccessToken, JiraClient.oauth_util);

Accounts.addAutopublishFields(
    {
        forLoggedInUser: ['services.jira'],
        forOtherUsers: []
    }
);

Accounts.oauth.registerService("jira");
OAuth.registerService("jira", "1.0-jira", {}, (oauthInfo, options) => {

    let
        jiraClient = new JiraClient({
            host: oauthInfo.host,
            port: oauthInfo.port,
            protocol: oauthInfo.protocol,
            oauth: {
                consumer_key: oauthInfo.consumerKey,
                private_key: oauthInfo.privateKey,
                token: oauthInfo.accessToken,
                token_secret: oauthInfo.accessTokenSecret
            }
        }),
        myself = Meteor.wrapAsync(jiraClient.myself.getMyself, jiraClient.myself)({}),
        serviceData = {
            id: oauthInfo.host + "::" + myself.key,
            username: myself.name,
            name: myself.displayName,
            email: myself.emailAddress,
            host: oauthInfo.host,
            port: oauthInfo.port,
            protocol: oauthInfo.protocol,
            accessToken: OAuth.sealSecret(oauthInfo.accessToken),
            accessTokenSecret: OAuth.sealSecret(oauthInfo.accessTokenSecret)
        };

    return {
        serviceData: serviceData,
        options: {
            profile: {
                name: myself.displayName,
                email: myself.emailAddress
            }
        }
    };
});

OAuth._requestHandlers['1.0-jira'] = (service, query, res) => {

    let
        config = ServiceConfiguration.configurations.findOne({service: service.serviceName}),
        credentialSecret,
        oauthResponse;

    if (!config) throw new ServiceConfiguration.ConfigError(service.serviceName);

    if (query.requestTokenAndRedirect) {

        var callbackUrl = OAuth._redirectUri(
            service.serviceName,
            config,
            {
                state: query.state,
                jiraHost: query.jiraHost || config.jiraHost,
                jiraPort: query.jiraPort || config.jiraPort,
                jiraProtocol: query.jiraProtocol || config.jiraProtocol,
                cordova: (query.cordova === "true"),
                android: (query.android === "true")
            }
        );

        oauthResponse = getAuthorizeURL(
            {
                host: query.jiraHost || config.jiraHost,
                port: query.jiraPort || config.jiraPort,
                protocol: query.jiraProtocol || config.jiraProtocol,
                oauth: {
                    consumer_key: config.consumerKey,
                    private_key: config.privateKey,
                    callback_url: callbackUrl
                }
            }
        );

        // Keep track of request token so we can verify it on the next step
        OAuth._storeRequestToken(
            OAuth._credentialTokenFromQuery(query),
            oauthResponse.token,
            oauthResponse.token_secret
        );

        res.writeHead(302, {'Location': oauthResponse.url});
        res.end();

    } else {

        let requestTokenInfo = OAuth._retrieveRequestToken(OAuth._credentialTokenFromQuery(query));

        if (!requestTokenInfo) throw new Error("Unable to retrieve request token");

        if (query.oauth_token && query.oauth_token === requestTokenInfo.requestToken) {

            let
                accessToken = swapRequestTokenWithAccessToken(
                    {
                        host: query.jiraHost || config.jiraHost,
                        port: query.jiraPort || config.jiraPort,
                        protocol: query.jiraProtocol || config.jiraProtocol,
                        oauth: {
                            consumer_key: config.consumerKey,
                            private_key: config.privateKey,
                            token: requestTokenInfo.requestToken,
                            token_secret: requestTokenInfo.requestTokenSecret,
                            oauth_verifier: query.oauth_verifier
                        }
                    }
                ),
                oauthResult = service.handleOauthRequest(
                    {
                        host: query.jiraHost || config.jiraHost,
                        port: query.jiraPort || config.jiraPort,
                        protocol: query.jiraProtocol || config.jiraProtocol,
                        consumerKey: config.consumerKey,
                        privateKey: config.privateKey,
                        accessToken: accessToken,
                        accessTokenSecret: requestTokenInfo.requestTokenSecret
                    },
                    {query: query}
                ),
                credentialToken = OAuth._credentialTokenFromQuery(query);

            credentialSecret = Random.secret();

            OAuth._storePendingCredential(credentialToken, {
                serviceName: service.serviceName,
                serviceData: oauthResult.serviceData,
                options: oauthResult.options
            }, credentialSecret);
        }

        OAuth._renderOauthResults(res, query, credentialSecret);
    }

};
