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
    	setStatusMessage("User provisioning should happen in a separate window.<br/> \
Please enable popups, before retrying");
    } else {
        sessionStorage.setItem('osio-provisioning', new Date().getTime());
        window.blur();
        window.focus();
        window.location.reload();
    }
}

var osioProvisioningLogout;
var osioProvisioningURL;
var osioUser;

(function( window, undefined ) {
    var osioURLSuffix;
    
    if (window.location.host.includes('prod-preview')) {
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
        	setStatusMessage("Checking account linking");
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
                    setStatusMessage("Error while checking account linking");
                    sessionStorage.removeItem('osio-provisioning-popup-message');
                    return Promise.reject(request);
                }
            });
        });
    }
    
    function setUpNamespaces(keycloak) {
        sessionStorage.removeItem('osio-provisioning-popup-message');
        setStatusMessage("Setting up namespaces");
        
        return get(osioApiURL + "/user", keycloak.token)
        .then((request) => checkNamespacesCreated(keycloak, new Date().getTime() + 30000));
    }

    function checkNamespacesCreated(keycloak, timeLimit) {
    	setStatusMessage("Checking namespaces");
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
            try {
                json = JSON.parse(data.response);
                if (json &&
                        json.errors &&
                        json.errors[0]) {
                    var error = json.errors[0];
                    
                    if(error.code == "unauthorized_error" &&
                            error.detail.endsWith("' is not approved")) {
                            return error.detail.replace("' is not approved", "")
                            .replace("user '", "");
                    }
                    if(error.code == "forbidden_error" &&
                            error.detail == "user is not authorized to access OpenShift") {
                            return "unknown";
                    }
                } 
            } catch(err) {
            }
        }
    }
    
    var setStatusMessage;
    
    var scripts = document.getElementsByTagName("script");
    var originalKeycloakScript;
    var provisioningPage;
    for(var i=0; i<scripts.length;++i) {
        if (scripts[i].src && scripts[i].src.endsWith("RhCheKeycloak.js")) {
               originalKeycloakScript = scripts[i].src.replace("RhCheKeycloak.js", "OIDCKeycloak.js");
               provisioningPage = scripts[i].src.replace("RhCheKeycloak.js", "provision.html");
               console.log("originalKeycloakScript = ", originalKeycloakScript);
               console.log("OSIO provisioning page = ", provisioningPage);
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
            kc.logout();
            return false;
        };
        var originalInit = kc.init;
        kc.init = function (initOptions) {
            var finalPromise = createPromise();

            var provisioningMessageDiv = document.createElement('div');
            provisioningMessageDiv.id = "osio-provisioning-frame";
            provisioningMessageDiv.style = "display: none; height: 100%; z-index: 999; position:fixed; padding:0; margin:0; top:0; left:0; width: 100%; height: 100%; background:rgba(255,255,255,1);";
            provisioningMessageDiv.innerHTML = '<iframe style="border: 0px; width: 100%; height: 100%" src="' + provisioningPage +  '"></iframe>';
            document.body.appendChild(provisioningMessageDiv);
            
            if (document.getElementsByClassName('ide-page-loader-content').length > 0) {
                var pageLoaderDiv = document.getElementsByClassName('ide-page-loader-content')[0];
                var loaderImage = pageLoaderDiv.getElementsByTagName("img")[0];
                if (loaderImage) {
                	loaderImage.src = "/dashboard/assets/branding/loader.svg";
                }
                
                var statusDiv = document.createElement('div');
                statusDiv.style = "text-align: center; position: fixed; top: 0; bottom: 0; left: 0; right: 0; margin: auto; height: 100%;";
                statusDiv.innerHTML = '\
                	<p id="osio-provisioning-status" style="position: relative; top: 50%; margin-top: 60px; font-weight: 500; font-size: larger; color: #bbb;"></p>';
                pageLoaderDiv.appendChild(statusDiv);
                setStatusMessage = function(message) {
                	document.getElementById("osio-provisioning-status").innerHTML = lastOSIOPopupMessage;
                }
            } else {
                setStatusMessage = function(message) {}
            }
            
            var lastOSIOPopupMessage = sessionStorage.getItem('osio-provisioning-popup-message');
            if (lastOSIOPopupMessage) {
              setStatusMessage(lastOSIOPopupMessage);
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
            	  setStatusMessage("Eclipse Che resources successfully granted");
                  finalPromise.setSuccess(arg);
              })
              .catch((error) => {
                  finalPromise.setError(error);
              });
            }).error(function(data) {
                    var keycloak = kc;
                if (data && (data.status == 403 || data.status == 401) && userNeedsApproval(data)) {
                    osioUser = userNeedsApproval(data);
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
                      setStatusMessage("Error during the creation of the <strong>OpenShift.io</strong> account.<br/>Please contact the support.");
                      finalPromise.setError(data);
                    } else {
                      if (!isProvisioning) {
                    	  if (osioUser != 'unknown') {
                        	  document.getElementById('osio-provisioning-frame').contentWindow.document.getElementById('osio-user-placeholder').innerHTML=", " + osioUser;
                    	  }
                    	  provisioningMessageDiv.style.display = 'block';
                      } else {
                            var message = "Provisioning the user for <strong>OpenShift.io</strong>";
                            sessionStorage.setItem('osio-provisioning-popup-message', message);
                            setStatusMessage(message);
                            setTimeout(function(){
                                window.location.reload();
                            }, 1000);
                      }
                    }
                } else {
                	setStatusMessage("Error during authentication");
                    var w = window.open('', 'osio_provisioning');
                    w && w.close();
                    sessionStorage.removeItem('osio-provisioning');
                        sessionStorage.removeItem('osio-provisioning-popup-message')                        
                    finalPromise.setError(data);
                }
            });
            
            return finalPromise.promise;
        }
        return kc;
    }
})( window );
