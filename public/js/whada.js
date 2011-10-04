$.template("userItemTemplate",
           '<li style="list-style-type: none;">' +
           '  <div class="username" style="font-size: large; font-weight: bold;">${UserName}</div>' +
           '  <ul class="items ui-widget ui-helper-clearfix">' +
           '    {{each Privileges}}' +
           '    <li class="ui-state-default ui-corner-all">${$value}</li>' +
           '    {{/each}}' +
           '  </ul>' +
           '</li>');

$.template("privilegeItemTemplate",
           '<li style="list-style-type: none;">' +
           '  <div class="privilege" style="font-size: large; font-weight: bold;">${PrivilegeName}</div>' +
           '  <ul class="items ui-widget ui-helper-clearfix">' +
           '    {{each Users}}' +
           '    <li class="ui-state-default ui-corner-all">${$value}</li>' +
           '    {{/each}}' +
           '  </ul>' +
           '</li>');

function load_users_list(){};

function load_privileges_list(){};

function load_privileges_admin_list(){};

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

