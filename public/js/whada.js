$(function(){
  load_page();
});

function load_page() {
  load_privileges_list();
  load_users_list();

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
      $(this).siblings('ul').slideToggle(80);
      if ($(this).hasClass('username')) {
        $('#checker_username').val($(this).text());
        if (whada_logged_in_as_admin) {
          $('#operator_user').text($(this).text());
        }
      }
      if ($(this).hasClass('privilege')) {
        $('#checker_privilege').val($(this).text());
        if (whada_logged_in_as_admin) {
          $('#operator_priv').text($(this).text());
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
          var username = $(this).closest('.items').siblings('.username').text();
          var parts = $(this).text().split(':');
          $('#operator_user').text(username);
          $('#operator_priv').text(parts[0]);
          $('#operator_status').text(parts[1]);
          $('#checker_username').val(username);
          $('#checker_privilege').val(parts[0]);
        });
      return false;
    });
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
  $.get('/privs', function(data){
    data.forEach(function(item){
      insert_privilege_into_list(item, '#privileges-list');
    });
    re_assign_events();
  });
};

function load_privileges_admin_list(){
  $.get('/admin_privs', function(data){
    data.forEach(function(item){
      insert_privilege_into_list(item, '#privileges-admin-list');
    });
    re_assign_events();
  });
};

$.template("userItemTemplate",
           '<li style="list-style-type: none;">' +
           '  <div class="username" style="font-size: large; font-weight: bold;">${UserName}</div>' +
           '  <ul class="items ui-widget ui-helper-clearfix">' +
           '    {{each Privileges}}' +
           '    <li class="operation_item ui-state-default ui-corner-all">${$value}</li>' +
           '    {{/each}}' +
           '  </ul>' +
           '</li>');

function insert_user_into_list(user, target){
  var privs = [];
  for (var name in user.privileges) {
    privs.push(name);
  }
  $.tmpl("userItemTemplate", [{UserName:user.username, Privileges:privs.sort().map(function(p){return p + ':' + user.privileges[p];})}])
    .appendTo(target);
};

function load_users_list(){
  $.get('/users', function(data){
    data.forEach(function(item){
      insert_user_into_list(item, '#users-list');
    });
    re_assign_events();
  });
};

function checker_execute(){
  var username = $('#checker_username').val();
  var privilege = $('#checker_privilege').val();
  if (username.length < 1 || privilege.length < 1) {
    show_dialog('Error', 'blank username or password', {"OK":function(){$('#dialog').dialog('close');}});
    return;
  }
  $.get('/check', {username:username, privilege:privilege}, function(data){
    show_dialog('Checker result', data['result'], {"OK":function(){$('#dialog').dialog('close');}});
  });
};

function operator_execute(event){
  var matched = /^operator_(.*)$/.exec($(event.target).closest('a').attr('id'));
  var operation = matched[1];
  var priv = $('#operator_priv').text();
  if (priv.length < 1) {
    show_dialog('Error', 'privilege not selected', {"OK":function(){$('#dialog').dialog('close');}});
    return;
  }
  if (operation === 'always_allow' || operation === 'default_allow' || operation === 'default_deny' || operation === 'always_deny'){
    $.post('/priv/update', {privilege:priv, dst_type:operation}, function(data){
      if (data.result)
        show_dialog('Success', data.message, {"OK":function(){$('#dialog').dialog('close'); reload_page();}});
      else
        show_dialog('Error', data.message, {"OK":function(){$('#dialog').dialog('close');}});
    });
    return;
  }
  else if (operation === 'allow' || operation === 'deny' || operation === 'remove') {
    var username = $('#operator_user').text();
    if (username.length < 1) {
      show_dialog('Error', 'user not selected', {"OK":function(){$('#dialog').dialog('close');}});
      return;
    }
    $.post('/user/update', {username:username, privilege:priv, operation:operation}, function(data){
      if (data.result)
        show_dialog('Success', data.message, {"OK":function(){$('#dialog').dialog('close'); reload_page();}});
      else
        show_dialog('Error', data.message, {"OK":function(){$('#dialog').dialog('close');}});
    });
    return;
  }
};