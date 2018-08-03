/*
 * Copyright (c) 2012-2018 Red Hat, Inc.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *   Red Hat, Inc. - initial API and implementation
 */
/*
 * This is a modified version of the Keycloak Javascript Adapter whose 
 * original sources can be found there: 
 * https://github.com/keycloak/keycloak/blob/master/adapters/oidc/js/src/main/resources/keycloak.js
 * 
 * Modifications allow using the Keycloak Javascript Adapter library with alternate OIDC-compliant providers,
 * provided that they produce access tokens as JWT tokens with `iat` and `exp` claims.
 */

function provision_osio(redirect_uri) {
    var provisioningWindow = window.open('https://developers.redhat.com/auth/realms/rhd/protocol/openid-connect/logout?redirect_uri=' + encodeURIComponent(redirect_uri), 'osio_provisioning');
    if(! provisioningWindow) {
        document.getElementById("osio-provisioning-status").innerHTML = "User provisioning should happen in a separate window.<br/> \
Please enable popups, before retrying";
    } else {
        sessionStorage.setItem('osio-provisioning', new Date().getTime());
        window.blur();
        window.focus();
        window.location.reload();
    }
}

var osioProvisioningLogout;

(function( window, undefined ) {
    var osioURLSuffix;
    var osioProvisioningURL;
    
    if (window.location.host.includes('-preview')) {
        osioURLSuffix = 'prod-preview.openshift.io';
        osioProvisioningURL = "https://manage.openshift.com/openshiftio?cluster=starter-us-east-2a"
    } else {
        osioURLSuffix = 'openshift.io';
        osioProvisioningURL = "https://manage.openshift.com/register/openshiftio_create"
    }

    var osioApiURL = 'https://api.' + osioURLSuffix + '/api';
    var osioAuthURL = 'https://auth.' + osioURLSuffix + '/api';

    function createPromise() {
        var p = {
            setSuccess: function(result) {
                p.success = true;
                p.result = result;
                if (p.successCallback) {
                    p.successCallback(result);
                }
            },

            setError: function(result) {
                p.error = true;
                p.result = result;
                if (p.errorCallback) {
                    p.errorCallback(result);
                }
            },

            promise: {
                success: function(callback) {
                    if (p.success) {
                        callback(p.result);
                    } else if (!p.error) {
                        p.successCallback = callback;
                    }
                    return p.promise;
                },
                error: function(callback) {
                    if (p.error) {
                        callback(p.result);
                    } else if (!p.success) {
                        p.errorCallback = callback;
                    }
                    return p.promise;
                }
            }
        }
        return p;
    }


    function get(url, token) {
        return new Promise((resolve, reject) => {
            var request = new XMLHttpRequest();
            request.onerror = request.onabort = function(error) {
                reject(error);
            };
            request.onload = function() {
                if (request.status == 200) {
                    resolve(this)
                } else {
                    reject(this);
                }
            };

            request.open("GET", url, true);
            if (token) {
                request.setRequestHeader("Authorization", "Bearer " + token);
            }
            request.send();
        });
    }
    
    function performAccounkLinking(keycloak) {
        return get(osioApiURL + "/users?filter%5Busername%5D=" + encodeURIComponent(keycloak.tokenParsed.preferred_username), keycloak.token)
        .then((request) => {
            data = JSON.parse(request.responseText).data;
            if (data && data[0]) {
                return data[0].attributes.cluster;
            } else {
                sessionStorage.removeItem('osio-provisioning-popup-message');
                return Promise.reject("cannot find cluster for user: " + keycloak.tokenParsed.preferred_username)
            }
        })
        .then((cluster) => {
            document.getElementById("osio-provisioning-status").innerHTML = "Checking account linking";
            return get(osioAuthURL + "/token?for=" + encodeURIComponent(cluster), keycloak.token)
            .catch((request) => {
                json = JSON.parse(request.responseText);
                if (request.status == 401 &&
                        json &&
                        json.errors &&
                        json.errors[0] &&
                        json.errors[0].detail == "token is missing") {
                    return get(osioAuthURL + "/token/link?for=" + encodeURIComponent(cluster) + "&redirect=" + encodeURIComponent(window.location), keycloak.token)
                    .then((request) => {
                        var json = JSON.parse(request.responseText);
                        if (json && json.redirect_location) {
                            sessionStorage.setItem('osio-provisioning-popup-message', "Performing account linking");
                            window.location.replace(json.redirect_location);
                        } else {
                            sessionStorage.removeItem('osio-provisioning-popup-message');
                            return Promise.reject("Cannot get account linking page for user: " + keycloak.tokenParsed.preferred_username)
                        }
                    });
                } else {
                    console.log("Error while checking account linking", request);
                    document.getElementById("osio-provisioning-status").innerHTML = "Error while checking account linking";
                    sessionStorage.removeItem('osio-provisioning-popup-message');
                    return Promise.reject(request);
                }
            });
        });
    }
    
    function setUpNamespaces(keycloak) {
        sessionStorage.removeItem('osio-provisioning-popup-message');
        document.getElementById("osio-provisioning-status").innerHTML = "Setting up namespaces";
        
        return get(osioApiURL + "/user", keycloak.token)
        .then((request) => checkNamespacesCreated(keycloak, new Date().getTime() + 30000));
    }

    function checkNamespacesCreated(keycloak, timeLimit) {
        document.getElementById("osio-provisioning-status").innerHTML = "Checking namespaces";
        return get(osioApiURL + "/user/services", keycloak.token)
        .catch((error) => {
            console.log("Error while checking namespaces: ", error);
            if (new Date().getTime() < timeLimit) {
                return new Promise((resolve, reject) => {
                    setTimeout(function(){
                        resolve(checkNamespacesCreated(keycloak, timeLimit));
                    }, 2000);
                })
            } else {
                return Promise.reject("Error when checking namespaces: ", error);
            }
        });
    }
    
    function userNeedsApproval(data) {
        if (data && (data.status == 403 || data.status == 401)) {
            json = JSON.parse(data.response);
            if (json &&
                json.errors &&
                json.errors[0] &&
                json.errors[0].code == "unauthorized_error" &&
                json.errors[0].detail.endsWith("' is not approved")) {
                return json.errors[0].detail.replace("' is not approved", "")
                .replace("user '", "");
            }
        }
    }
    
    var scripts = document.getElementsByTagName("script");
    var originalKeycloakScript;
    for(var i=0; i<scripts.length;++i) {
        if (scripts[i].src && scripts[i].src.endsWith("RhCheKeycloak.js")) {
               originalKeycloakScript = scripts[i].src.replace("RhCheKeycloak.js", "OIDCKeycloak.js");
               console.log("originalKeycloakScript = ", originalKeycloakScript);
               break;
        }
    }

    if (! originalKeycloakScript) {
        throw "Cannot find current script named 'RhCheKeycloak.js'";
    }
    
    request = new XMLHttpRequest();
    request.open('GET', originalKeycloakScript, false);
    request.send();

    source = request.responseText;
    eval(source);
    var originalKeycloak = window.Keycloak;
    window.Keycloak = function(config) {
        kc = originalKeycloak(config);
        osioProvisioningLogout = function() {
        	kc.login({prompt: 'login', maxAge: '0', loginHint: ''});
        };
        var originalInit = kc.init;
        kc.init = function (initOptions) {
            var finalPromise = createPromise();

            var script = document.createElement("script");
            script.type = "text/javascript";
            script.language = "javascript";
            script.async = true;
            script.src = "https://unpkg.com/simple-popup@0.1.1/simple-popup.js";

            script.onload = function() {
                var notificationDiv = document.createElement('div');
                notificationDiv.id = "osio-provivioning-popup";
                // notificationDiv.className = "popup-wrapper hide";
                notificationDiv.style = "display: none; font-family: Helvetica,Arial,sans-serif; position: absolute; width: 400px; height: 200px; z-index: 999; background-color: #fff; border: 1px solid #ddd; border-radius: 5px; box-shadow: 0 2px 8px #aaa; overflow: hidden; box-sizing: unset;";
                notificationDiv.innerHTML = '\
<div style="height: 100%; box-sizing: unset;"> \
    <div style="padding: 10px 15px; background-color: #f4f4f4; border-bottom: 1px solid #f0f0f0; height: 30px; box-sizing: unset;"> \
        <button type="button" class="osio-provisioning-popup-close" style="float: right; margin-top: 2px; padding: 0; font-size: 24px; line-height: 1; border: 0; background: transparent; color: #aaa; cursor: pointer;">×</button>\
        <h3 style="margin: 0; line-height: 1.5em; color: #333;">User setup</h3> \
    </div>\
    <div style="padding: 10px 15px; color: #555; background-image: url(https://che.openshift.io/dashboard/assets/branding/loader.svg); background-repeat:  no-repeat;background-position:  center;background-size: 50%;background-origin: padding-box; height:230px; min-height: 70%; opacity: 0.3; box-sizing: unset;">\
    </div>\
    <div style="margin-top: -250px; padding: 10px 15px; color: #333; height:80%; min-height: 70%; opacity: 1; text-align: center; box-sizing: unset;">\
        <p id="osio-provisioning-status" style="font-weight: 500; font-size: larger;">Preparing the user environment</p> \
    </div> \
</div>';
                document.body.appendChild(notificationDiv);

                var popupOpts = {
                    width: 400,
                    height: 300,
                    closeBtnClass: 'osio-provisioning-popup-close'
                };

                var popup;
                if (typeof($) !== 'undefined' && $.fn && $.fn.popup) {
                    popup = $("#osio-provivioning-popup").popup(popupOpts);
                } else {
                    // As a native plugin
                    popup = new Popup(notificationDiv, popupOpts);
                }

                
                    var lastOSIOPopupMessage = sessionStorage.getItem('osio-provisioning-popup-message');
                    if (lastOSIOPopupMessage) {
                      document.getElementById("osio-provisioning-status").innerHTML = lastOSIOPopupMessage;
                        popup.open();
                    }
                
                var promise = originalInit(initOptions);
                promise.success(function(arg) {
                    var keycloak = kc;
                  sessionStorage.removeItem('osio-provisioning');
                  var w = window.open('', 'osio_provisioning');
                  w && w.close();
                  performAccounkLinking(keycloak)
                  .then(()=>{
                      return setUpNamespaces(keycloak);
                  })
                  .then(() => {
                      document.getElementById("osio-provisioning-status").innerHTML = "User successfully prepared";
                      setTimeout(function() {
                          popup.close();
                          finalPromise.setSuccess(arg);
                      }, 1000);
                  })
                  .catch((error) => {
                      finalPromise.setError(error);
                  });
                }).error(function(data) {
                        var keycloak = kc;
                    popup.open();
                    if (data && (data.status == 403 || data.status == 401) && userNeedsApproval(data)) {
                      var userToBeApproved = userNeedsApproval(data);
                        var lastProvisioningDate = sessionStorage.getItem('osio-provisioning');
                        var isProvisioning = false;
                        var provisioningTimeoutFailure = false;
                        if (lastProvisioningDate) {
                          if (new Date().getTime() < parseInt(lastProvisioningDate) + 30000) {
                              isProvisioning = true;
                          } else {
                                  provisioningTimeoutFailure = true;
                          }
                        }
                        
                        if (provisioningTimeoutFailure) {
                          sessionStorage.removeItem('osio-provisioning');
                              sessionStorage.removeItem('osio-provisioning-popup-message')                        
                          document.getElementById("osio-provisioning-status").innerHTML = "Error during the creation of the <strong>OpenShift.io</strong> account.<br/>Please contact the support.";
                          finalPromise.setError(data);
                        } else {
                          if (!isProvisioning) {
                                document.getElementById("osio-provisioning-status").innerHTML = "To have access to <strong>che.openshift.io</strong>, user <strong>" + userToBeApproved + "</strong> must be enabled on the underlying <strong>Openshift.io</strong> platform.<br/>" +
                                        "Please click on the link below. This will open a new tab and request you to login again with user  be careful to login with the <strong>" + userToBeApproved + "</strong> user.<br/>" +
                                        "When finished, you will be brought back to <strong>che.openshift.io</strong>. If not contact support.<br/>" +
                                        "<a href='about:blank' target='osio_provisioning' onclick='provision_osio(\"" + osioProvisioningURL + "\")' style='position: relative;'>Enable user <strong>" + userToBeApproved + "</strong> on <strong>OpenShift.io</strong></a>" +
                                        "<br/>" +
                                        "<a href='' onclick='osioProvisioningLogout()' style='position: relative;'>Use a different user</a>";
                          } else {
                                    var message = "Provisioning the user for <strong>OpenShift.io</strong>";
                                sessionStorage.setItem('osio-provisioning-popup-message', message);
                                document.getElementById("osio-provisioning-status").innerHTML = message;
                                setTimeout(function(){
                                    window.location.reload();
                                }, 1000);
                          }
                        }
                    } else {
                        document.getElementById("osio-provisioning-status").innerHTML = "Error during authentication";
                        var w = window.open('', 'osio_provisioning');
                        w && w.close();
                        sessionStorage.removeItem('osio-provisioning');
                            sessionStorage.removeItem('osio-provisioning-popup-message')                        
                        finalPromise.setError(data);
                    }
                });
            };
            
            script.onerror = script.onabort = function() {
                finalPromise.setError("Could not load script: https://unpkg.com/simple-popup@0.1.1/simple-popup.js");
            };
                                
            document.head.appendChild(script);
            
            return finalPromise.promise;
        }
        return kc;
    }
})( window );
