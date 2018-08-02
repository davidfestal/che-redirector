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

function provision_osio() {
	var provisioningWindow = window.open('https://developers.redhat.com/auth/realms/rhd/protocol/openid-connect/logout?redirect_uri=https%3A%2F%2Fmanage.openshift.com%2Fregister%2Fopenshiftio_create', 'osio_provisioning');
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

(function( window, undefined ) {

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
        document.getElementById("osio-provisioning-status").innerHTML = "Getting user cluster";
        return get("https://api.openshift.io/api/users?filter%5Busername%5D=" + encodeURIComponent(keycloak.tokenParsed.preferred_username), keycloak.token)
        .then((request) => {
        	data = JSON.parse(request.responseText).data;
        	if (data && data[0]) {
        		return data[0].attributes.cluster;
        	} else {
        		return Promise.reject("cannot find cluster for user: " + keycloak.tokenParsed.preferred_username)
        	}
        })
        .then((cluster) => {
            document.getElementById("osio-provisioning-status").innerHTML = "Checking account linking";
        	return get("https://auth.openshift.io/api/token?for=" + encodeURIComponent(cluster), keycloak.token)
        	.catch((request) => {
        		json = JSON.parse(request.responseText);
        		if (request.status == 401 &&
        				json &&
        				json.errors &&
        				json.errors[0] &&
        				json.errors[0].detail == "token is missing") {
                    return get("https://auth.openshift.io/api/token/link?for=" + encodeURIComponent(cluster) + "&redirect=" + encodeURIComponent(window.location), keycloak.token)
                    .then((request) => {
                        var json = JSON.parse(request.responseText);
                        if (json && json.redirect_location) {
                            window.location.replace(json.redirect_location);
                        } else {
                            return Promise.reject("Cannot get account linking page for user: " + keycloak.tokenParsed.preferred_username)
                        }
                    });
        		} else {
                    console.log("Error while testing linked account", request);
        			return Promise.reject(request);
        		}
        	});
        });
    }
    
    function setUpNamespaces(keycloak) {
        document.getElementById("osio-provisioning-status").innerHTML = "Setting up namespaces";
        
        return get("https://api.openshift.io/api/user", keycloak.token)
        .then((request) => checkNamespacesCreated(keycloak, new Date().getTime() + 30000));
    }

    function checkNamespacesCreated(keycloak, timeLimit) {
        document.getElementById("osio-provisioning-status").innerHTML = "Checking namespaces";
        return get("https://api.openshift.io/api/user/services", keycloak.token)
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
				//notificationDiv.className = "popup-wrapper hide";
				notificationDiv.style = "display: none; font-family: Helvetica,Arial,sans-serif; position: absolute; width: 400px; height: 200px; z-index: 999; background-color: #fff; border: 1px solid #ddd; border-radius: 5px; box-shadow: 0 2px 8px #aaa; overflow: hidden;";
				notificationDiv.innerHTML = '<div> \
				<div style="padding: 10px 15px; background-color: #f4f4f4; border-bottom: 1px solid #f0f0f0;"> \
				<button type="button" class="osio-provisioning-popup-close" style="float: right; margin-top: 2px; padding: 0; font-size: 24px; line-height: 1; border: 0; background: transparent; color: #aaa; cursor: pointer;">×</button>\
				<h3 style="margin: 0; line-height: 1.5em; color: #333;">Please wait...</h3> \
				</div> \
				<div style="padding: 10px 15px; color: #555;"> \
				<p stype = "text-align: center;" id="osio-provisioning-status">Preparing the user environment</p> \
				</div> \
				</div>';
				document.body.appendChild(notificationDiv);

				var popupOpts = {
				    width: 400,
				    height: 300,
				    closeBtnClass: 'osio-provisioning-popup-close'
				};

				var popup;
				if ($ && $.fn && $.fn.popup) {
					popup = $("#osio-provivioning-popup").popup(popupOpts);
				} else {
				    // As a native plugin
				    popup = new Popup(notificationDiv, popupOpts);
				}
				
				var promise = originalInit(initOptions);
	            promise.success(function(arg) {
	          	  var keycloak = kc;
	          	  popup.open();
	              document.getElementById("osio-provisioning-status").innerHTML = "User provisioned user for Openshift.io";
	              sessionStorage.removeItem('osio-provisioning');
	              var w = window.open('', 'osio_provisioning');
	              w && w.close();
	              performAccounkLinking(keycloak)
	              .then(()=>{
	            	  return setUpNamespaces(keycloak);
	              })
	              .then(() => {
	                  document.getElementById("osio-provisioning-status").innerHTML = "Authenticated";
	                  document.getElementById("query").innerHTML = window.location;
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
		            if (data && data.status == 403) {
		          	  var lastProvisioningDate = sessionStorage.getItem('osio-provisioning');
		          	  var isProvisioning = false;
		          	  if (lastProvisioningDate) {
		          		if (parseInt(lastProvisioningDate) < new Date().getTime() + 30000) {
		                      isProvisioning = true;
		                  } else {
		                      sessionStorage.removeItem('osio-provisioning');
		                  }
		          	  }
		          	  if (!isProvisioning) {
		                    document.getElementById("osio-provisioning-status").innerHTML = "In order to use <strong>che.openshift.io</strong>, your account should be first created on the underlying <strong>openshift.io</strong> platform.<br/>" +
		                    		"Please click the link below to confirm your account creation.<br/>A new tab will open and request you to login again. Please login with the same user account as you just registered.<br/><br/>" +
		                    		"As soon as it your user is created, the new tab will close and you will be brought back to <strong>che.openshift.io</strong>. If not please contact support.<br/><br/>" +
		                    		"<a href='about:blank' target='osio_provisioning' onclick='provision_osio()'>Create my user on OpenShift.io<strong>Openshift</strong></a>";
		          	  } else {
		                    document.getElementById("osio-provisioning-status").innerHTML = "Provisioning the user for OpenShift.io in a new tab... click <a href='https://manage.openshift.com/account/index' target='osio_provisioning'>here</a> to follow the registration.";
		                    setTimeout(function(){
		                        window.location.reload();
		                    }, 1000);
		          	  }
		            } else {
		                document.getElementById("osio-provisioning-status").innerHTML = "Error during authentication";
		                var w = window.open('', 'osio_provisioning');
		                w && w.close();
		                sessionStorage.removeItem('osio-provisioning');
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
