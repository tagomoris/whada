$(function(){
  load_page();
});

function load_page() {
  load_privileges_list();
  load_users_list();

  $("a.searcher_username").button();
  $('a#searcher_username')
    .unbind()
    .click(searcher_execute);

  $('#checker_bar')
    .unbind()
    .click(function(){
      $('.control #checker').slideToggle(50);
    });
  $("a.checker_button").button();
  $('a#checker_button')
    .unbind()
    .click(checker_execute);

  if (whada_logged_in_as_admin) {
    load_privileges_admin_list();

    $("a.operator_button,a.panel_button").button();
    $('#operator_bar')
      .unbind()
      .click(function(){
        $('.control #operator').slideToggle(50);
      });
    $('.operator_button')
      .unbind()
      .click(operator_execute);
    $('.panel_button')
      .unbind()
      .click(panel_execute);

    $('#panel_bar')
      .unbind()
      .click(function(){
        $('.control #panel').slideToggle(50);
      });
  }
};

function reload_page() {
  $('#privileges-list').empty();
  $('#users-list').empty();
  $("a.checker_button").button('destroy');

  if (whada_logged_in_as_admin) {
    $('#privileges-admin-list').empty();
    $("a.operator_button,a.panel_button").button('destroy');
  }
  load_page();
};

function re_assign_events() {
  $('div.username,div.privilege')
    .die('click')
    .live('click', function() {
      var action = ($(this).siblings('ul').css('display') === 'none' ? 'dropdown' : 'rollup');
      $(this).siblings('ul').slideToggle(80);
      if ($(this).hasClass('username')) {
        var username = $(this).data('username');
        $('#checker_username').val(username);
        if (whada_logged_in_as_admin) {
          set_priv_operator('username', action, {username:username});
          $('#drop_user_name').val(username);
        }
      }
      if ($(this).hasClass('privilege')) {
        var privname = $(this).text();
        $('#checker_privilege').val(privname);
        if (whada_logged_in_as_admin) {
          set_priv_operator('privilege', action, {privilege:privname});
          $('#drop_priv_name').val(privname);
        }
      }
      $('ul.items li')
        .unbind('hover')
        .hover(
          function() { $(this).addClass('ui-state-hover'); }, 
          function() { $(this).removeClass('ui-state-hover'); }
        );
      $('ul.items li.operation_item')
        .unbind('click')
        .click(function(){
          $('.control #operator').slideDown(50);
          var username = $(this).closest('.items').siblings('.username').data('username');
          var parts = $(this).text().split(':');
          set_priv_operator('full', 'full', {username:username, privilege:parts[0], status:parts[1]});
          $('#checker_username').val(username);
          $('#checker_privilege').val(parts[0]);
        });
      return false;
    });
};

function set_priv_operator(datatype, action, set){
  if (action === 'full') {
    $('#operator_user').text(set.username);
    $('#operator_priv').text(set.privilege);
    $('#operator_status').text(set.status);
    return;
  }
  if (action === 'rollup') {
    if (datatype === 'username') {
      $('#operator_user,#operator_priv,#operator_status').text('');
    } else { /* privilege */
      $('#operator_priv,#operator_status').text('');
    }
    return;
  }
  /* dropdown */
  if (datatype === 'username') {
    $('#operator_user').text(set.username);
    var priv = $('#operator_priv').text();
    if (priv.length < 1)
      return;
    var userdata = user_data_cached(set.username);
    if (userdata && userdata[priv]) {
      $('#operator_status').text(userdata[priv]);
    }else{
      $('#operator_status').text('');
    }
    return;
  }
  /* dropdown && privilege */
  $('#operator_priv').text(set.privilege);
  var username = $('#operator_user').text();
  if (username.length < 1)
    return;
  var userdata2 = user_data_cached(username);
  if (userdata2 && userdata2[set.privilege]) {
    $('#operator_status').text(userdata2[set.privilege]);
  }else{
    $('#operator_status').text('');
  }
};

function show_dialog(title, message, buttons){
  $('#dialog').attr('title', title);
  $('#dialog_message').text(message);
  $('#dialog').bind('dialogclose', function(event, ui){
    $('#dialog').dialog('destroy');
    $('#dialog').attr('title', '');
    $('#dialog_message').text('');
  });
  $('#dialog').dialog({
    autoOpen: true,
    width: 400,
    buttons: buttons
  });
};

$.template("privilegeItemTemplate",
           '<li style="list-style-type: none;">' +
           '  <div class="privilege" style="font-size: large; font-weight: bold;">${PrivilegeName}</div>' +
           '  <ul class="items ui-widget ui-helper-clearfix">' +
           '    <li class="ui-state-default ui-corner-all">${PrivilegeType}</li>' +
           '  </ul>' +
           '</li>');

function insert_privilege_into_list(priv, target){
  $.tmpl("privilegeItemTemplate", [{PrivilegeName: priv.name, PrivilegeType: priv.type}])
    .appendTo(target);
};

function load_privileges_list(){
  $.get('/privs?' + (new Date()).getTime(), function(data){
    data.forEach(function(item){
      insert_privilege_into_list(item, '#privileges-list');
    });
    re_assign_events();
  });
};

function load_privileges_admin_list(){
  $.get('/admin_privs?' + (new Date()).getTime(), function(data){
    data.forEach(function(item){
      insert_privilege_into_list(item, '#privileges-admin-list');
    });
    re_assign_events();
  });
};

$.template("userItemTemplate",
           '<li style="list-style-type: none;">' +
           '  <div class="username" style="font-size: large; font-weight: bold;" data-username="${UserName}">' +
           '    ${UserName}<span class="limited">${Limited}</span></div>' +
           '  <ul class="items ui-widget ui-helper-clearfix">' +
           '    {{each Privileges}}' +
           '    <li class="operation_item ui-state-default ui-corner-all">${$value.text}</li>' +
           '    {{/each}}' +
           '  </ul>' +
           '</li>');

function insert_user_into_list(user, target){
  var privs = [];
  for (var name in user.privileges) {
    privs.push(name);
  }
  $.tmpl("userItemTemplate", [{
    UserName:user.username,
    Limited:(user.limited ? ' (limited)' : ''),
    Privileges:privs.sort().map(function(p){return {name: p, status: user.privileges[p], text: p + ':' + user.privileges[p]};})
  }]).appendTo(target);
};

var users_data = {};
function load_users_list(){
  users_data = {};
  $.get('/users?' + (new Date()).getTime(), function(data){
    data.forEach(function(item){
      users_data[item.username] = item;
      insert_user_into_list(item, '#users-list');
    });
    re_assign_events();
  });
};

function user_data_cached(username){
  if (users_data[username]){
    return users_data[username].privileges;
  }
  return null;
};

function user_type_cached(username){
  if (users_data[username]){
    return users_data[username].limited || false;
  }
  return null;
}

function searcher_execute(){
  var username = $('#username_search').val();
  if (username.length < 1) {
    show_dialog('Error', 'blank username', {"OK":function(){$('#dialog').dialog('close');}});
  }
  $.get('/search?' + (new Date()).getTime(), {username:username}, function(data){
    show_dialog('Search result', data['result'], {"OK":function(){$('#dialog').dialog('close');}});
  });
}

function checker_execute(){
  var username = $('#checker_username').val();
  var privilege = $('#checker_privilege').val();
  if (username.length < 1 || privilege.length < 1) {
    show_dialog('Error', 'blank username or password', {"OK":function(){$('#dialog').dialog('close');}});
    return;
  }
  $.get('/check?' + (new Date()).getTime(), {username:username, privilege:privilege}, function(data){
    show_dialog('Checker result', data['result'], {"OK":function(){$('#dialog').dialog('close');}});
  });
};

function operator_execute(event){
  var matched = /^operator_(.*)$/.exec($(event.target).closest('a').attr('id'));
  var operation = matched[1];
  var priv = $('#operator_priv').text();
  var path;
  var args;
  if (operation === 'always_allow' || operation === 'default_allow' || operation === 'default_deny' || operation === 'always_deny'){
    if (priv.length < 1) {
      show_dialog('Error', 'privilege not selected', {"OK":function(){$('#dialog').dialog('close');}});
      return;
    }
    path = '/priv/update';
    args = {privilege:priv, dst_type:operation};
  }
  else if (operation === 'allow' || operation === 'deny' || operation === 'remove') {
    var username = $('#operator_user').text();
    if (username.length < 1) {
      show_dialog('Error', 'user not selected', {"OK":function(){$('#dialog').dialog('close');}});
      return;
    }
    if (priv.length < 1) {
      show_dialog('Error', 'privilege not selected', {"OK":function(){$('#dialog').dialog('close');}});
      return;
    }
    path = '/user/update';
    args = {username:username, privilege:priv, operation:operation};
  }
  else if (operation === 'limit') {
    var username2 = $('#operator_user').text();
    if (username2.length < 1) {
      show_dialog('Error', 'user not selected', {"OK":function(){$('#dialog').dialog('close');}});
      return;
    }
    path = '/user/toggle_limit';
    args = {username:username2};
  }
  else {
    show_dialog('Error', 'unknown operation (maybe bug):' + operation, {"OK":function(){$('#dialog').dialog('close');}});
    return;
  }
  $.post(path, args, function(data){
    if (data.result)
      show_dialog('Success', data.message, {"OK":function(){$('#dialog').dialog('close'); reload_page();}});
    else
      show_dialog('Error', data.message, {"OK":function(){$('#dialog').dialog('close');}});
  });
};

function panel_execute(event){
  var matched = /^panel_([a-z]+)_([a-z]+)$/.exec($(event.target).closest('a').attr('id'));
  var operation = (matched[1] === 'create') ? 'create' : 'drop';
  var datatype = (matched[2] === 'user') ? 'user' : 'priv';
  var value = $('input#' + operation + '_' + datatype + '_name').val();
  if (value.length < 1) {
    show_dialog('Error', 'operation target ' + operation + ' ' + datatype + ', not specified', {
      "OK":function(){$('#dialog').dialog('close');}});
    return;
  }
  var path = '/' + datatype + '/' + operation;
  $.post(path, {target:value}, function(data){
    if (data.result)
      show_dialog('Success', data.message, {"OK":function(){$('#dialog').dialog('close'); reload_page();}});
    else
      show_dialog('Error', data.message, {"OK":function(){$('#dialog').dialog('close');}});
  });
};
