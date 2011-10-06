$(function(){
  load_privileges_list();
  load_privileges_admin_list();
  load_users_list();
});

function re_assign_events() {
  $('div.username,div.privilege')
    .die('click')
    .live('click', function() {
      $(this).siblings('ul').slideToggle(80);
      $('ul.items li')
        .unbind('hover')
        .hover(
          function() { $(this).addClass('ui-state-hover'); }, 
          function() { $(this).removeClass('ui-state-hover'); }
        );
      return false;
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
           '    <li class="ui-state-default ui-corner-all">${$value}</li>' +
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

function create_queryitem_object(queryid, id_prefix){
  var query = shibdata.query_cache[queryid];
  if (! query)
    return '';
  var lastresult = query_last_result(query);
  var executed_at = (lastresult && lastresult.executed_at) || '-';
  var keyword_primary = (query.keywords && query.keywords.length > 0 && query.keywords[0]) || '-';
  return {
    QueryId: (id_prefix || '') + query.queryid,
    Information: executed_at + ', ' + keyword_primary,
    Statement: query.querystring,
    Status: query_current_state(query),
    Etc: timelabel_elapsed(lastresult.completed_at, lastresult.executed_at) +
      ((lastresult && lastresult.bytes && lastresult.lines &&
        (', ' + lastresult.bytes + ' bytes, ' + lastresult.lines + ' lines')) || '')
  };
};

function update_yours_tab(){
  $('#tab-yours')
    .empty()
    .append('<div><h3><a href="#">your queries</a></h3><div id="yours-idlist"></div></div>');
  if (execute_query_list().length > 0)
    $.tmpl("queryItemTemplate",
           execute_query_list().map(function(id){return create_queryitem_object(id, 'yours-');})
          ).appendTo('#tab-yours div div#yours-idlist');
};

