/**
 * Hosts the latest kibana3 and elasticsearch behind Google OAuth2 Authentication
 * with nodejs and express.
 * License: MIT
 * Copyright: Funplus Game Inc.
 * Author: Fang Li.
 * Project: https://github.com/fangli/kibana-authentication-proxy
 */

var express = require('express');
var https = require('https');
var http = require('http');
var fs = require('fs');

var config = require('./config');
var app = express();

var logger = require('bucker').createLogger(config.logging);

console.log('Server starting...');
logger.info("server starting...");
app.use(express.cookieParser());
app.use(express.session({ secret: config.cookie_secret }));
app.use(logger.middleware());

// Authentication
require('./lib/basic-auth').configureBasic(express, app, config);
require('./lib/google-oauth').configureOAuth(express, app, config);
require('./lib/cas-auth.js').configureCas(express, app, config);

// Setup ES proxy
require('./lib/es-proxy').configureESProxy(app, config.es_host, config.es_port,
          config.es_username, config.es_password);

// Serve config.js for kibana3
// We should use special config.js for the frontend and point the ES to __es/
app.get('/config.js', kibana3configjs);
app.get('/app/dashboards/*.json', dynamicDashboard);

// Serve all kibana3 frontend files
app.use('/', express.static(__dirname + '/kibana/src'));

run();

function run() {
  if (config.enable_ssl_port === true) {
    var options = {
      key: fs.readFileSync(config.ssl_key_file),
      cert: fs.readFileSync(config.ssl_cert_file),
    };
    https.createServer(options, app).listen(config.listen_port_ssl);
    console.log('Server listening on ' + config.listen_port_ssl + '(SSL)');
  }
  http.createServer(app).listen(config.listen_port);
  console.log('Server listening on ' + config.listen_port);
}

function dynamicDashboard(req, res){
    var user = req.session.user;
    var client = config.account[user];
    
    req.url = req.url.split('?')[0];
    var dashboard = JSON.parse(fs.readFileSync(__dirname+'/kibana/src/'+req.url,'utf8'));
    dashboard.index.pattern = '['+client+'-logstash-]YYYY.MM.DD';
    res.setHeader('Content-Type', 'application/json');
    var d = JSON.stringify(dashboard);
    res.end(d);
}

function getCurrentUser(req){
    var raw_index = config.kibana_es_index;
    var user_type = config.which_auth_type_for_kibana_index;
    var user;
    if (raw_index.indexOf('%user%') > -1) {
      if (user_type === 'google') {
        user = req.googleOauth.emails[0].value;
      } else if (user_type === 'basic') {
        user = req.user;
      } else if (user_type === 'cas') {
        user = req.session.cas_user_name;
      } else {
        user = 'unknown';
      }
      return user
    } else {
      return;
    }
}

function kibana3configjs(req, res) {
  req.session.user = getCurrentUser(req);
  req.session.client = config.account[req.session.user];
  console.log(req.session);

  function getKibanaIndex() {
      var raw_index = config.kibana_es_index;
      if(req.session.user){
        return raw_index.replace(/%user%/gi, req.session.client);
      }else{
        return raw_index;
      }
  }

  res.setHeader('Content-Type', 'application/javascript');
  res.end("define(['settings'], " +
    "function (Settings) {'use strict'; return new Settings({elasticsearch: '/__es', default_route     : '/dashboard/file/default.json'," +
      "kibana_index: '" +
      getKibanaIndex() +
      "', panel_names: ['histogram', 'map', 'pie', 'table', 'filtering', 'timepicker', 'text', 'hits', 'column', 'trends', 'bettermap', 'query', 'terms', 'sparklines'] }); });");
}
