/**** basic setup and preloading of stuff ****/
var tree_xslt_processor = new XSLTProcessor();
var detail_xslt_processor = new XSLTProcessor();

/* autocomplete input configs */
var ac_tree_search = { // search field in tree for faster access
    delay : 0,
    minLength : 0,
    source : [],
    select : function(event, ui) {
        var targets = $("#tree span:contains('" + ui.item.label + "')");
        // open the node if only one found (thats always the case currently).
        if (targets.length == 1) {
            $.get('/domad/node/' + encodeURIComponent(getDN(targets[0])), false, false, 'xml')
             .error(function (xhr) { alert(xhr.responseText); })
             .success( show_details );
        }
        // make sure we are visible
        targets.parentsUntil('#tree').filter('ul').each(function(i,n) { console.log(n); $(n).slideDown('fast', save_state)})
        $('#tree').scrollTo(targets);
    }
};
var ac_tree_context = { // context menu in tree.
    delay:0,
    minLength:0,
    source: ['add new Folder', 'add new Container', 'add new Group', 'delete'],
    select: function (event, ui) {
        var dn = getDN(this);
        switch (ui.item.value) {
            case 'add new Folder':
                var name = prompt('specify the folder name', 'newFolder');
                if (name) {
                    $.ajax({
                        type:'PUT', 
                        url:'/domad/childs/' + dn,
                        data: 'ou='+name,
                        dn : dn,
                        success: function () {
                            $.get('/domad/childs/'+encodeURIComponent(this.dn), false,false,'xml').success(display_tree);
                }})}
                break;
            case 'add new Group':
                var name = prompt('specify the folder name', 'newGroup');
                if (name) {
                    $.ajax({
                        type:'PUT', 
                        url:'/domad/childs/' + dn, 
                        data: 'udGroup='+name,
                        dn : dn,
                        success: function () {
                            $.get('/domad/childs/'+encodeURIComponent(this.dn), false,false,'xml').success(display_tree);
                }})}
                break;
            case 'add new Container':
                var name = prompt('specify the folder name', 'newContainer');
                if (name) {
                    $.ajax({
                        type:'PUT', 
                        url:'/domad/childs/' + dn, 
                        data: 'udHostContainer='+name,
                        dn : dn,
                        success: function () {
                            $.get('/domad/childs/'+encodeURIComponent(this.dn), false,false,'xml').success(display_tree);
                }})}
                break;
            case 'delete':
                // ask to delete if there are children.
                var sub = $(this.parentNode).next().find('li');
                if (sub.length > 0 && prompt('this node has ' + sub.length + ' children. Are you sure you want delete it?', 'yes').toLowerCase() != 'yes') return false;
                // ask again if children are hosts!
                sub = $(this.parentNode).next().find('.udhost');
                if (sub.length > 0 && prompt('this node has ' + sub.length +' HOST childs!!. Are you sure you want delete it?', 'no').toLowerCase() != 'yes') return false;
                $.ajax({
                    type:'DELETE', 
                    url:'/domad/childs/' + dn, 
                    dn : dn.substring(dn.indexOf(',')+1),
                    success: function () {
                        $.get('/domad/childs/'+encodeURIComponent(this.dn), false,false,'xml').success(display_tree);
                }})
                break;
        }
    }
};

var ac_detail_user_cache = {}
var ac_detail_user = {
    minLength: 3,
    source: function( request, response ) {
        // simple caching. TODO: if we already have a cache with less specific term, we should filter.
        if (request.term in ac_detail_user_cache) { return response(ac_detail_user_cache[request.term])}
        lastUserXhr = $.getJSON('/domad/users', request)
            .success(function(data, status, xhr) {
                if (xhr === lastUserXhr) {
                    ac_detail_user_cache[request.term] = data.map(function(o) { return {'value': o.uid, 'label':o.user}});
                    response(ac_detail_user_cache[request.term]);
                }
            })
            .error(function() { response({});});
    },
    close: function() { this.value = "";}
};

var ac_detail_group = {
    minLength : 0,
    delay : 0,
    source : [],
    close: function() { this.value = "";}
};
var ac_detail_group_with_members = {
    minLength : 0,
    delay : 0,
    source : [],
    close: function() { this.value = "";}
};
//load groups at start as those are static and small anyway
$.getJSON('/domad/groups').success(function(data) {
    ac_detail_group.source = data.map(function(o) { return { value:o.name, label:o.group};});
    ac_detail_group_with_members.source = data.filter(function(o) { return o.hasMembers; }).map(function(o) { return { value:o.name, label:o.group};});
});

var ac_detail_policy = {
    minLength : 0,
    delay : 0,
    // until we find a non-static way to do these, we jsut hardcode it.
    // FIXME: should parse the cf-engine-policies on startup.
    source : [
{'value': 'DMZ', 'label': 'DMZ: managed hosts to run in the URZ DMZ'},
{'value': 'hardened', 'label': 'hardened: slightly more secure system configuration but less comfort'},
{'value': 'spectrum', 'label' : 'spectrum: enable spectrum monitoring for this host'},
{'value': 'httpd', 'label': 'install and maintain apache web server'},
{'value': 'mysqld', 'label':'mysqld: install and run mysql server'},
{'value': 'postgresql', 'label': 'postgresql: install and run a postgresql server'},
{'value': 'vhosting', 'label': 'managed_hosting: enable httpd for webhosting (webdav, kerberos)'},
{'value': 'noupdate', 'label': 'noupdate: host will NOT be automatic updated every night (less secure!)'},
{'value': 'nostorage', 'label': 'nostorage: do not setup/use NFS'},
{'value': 'allow_foreign_nameservers', 'label': 'UNSUPPORTED: do not disable unknwon nameservers in resolv.conf'},
{'value': 'firewall_unmanaged', 'label':'UNSUPPORTED: disable firewall editing by cfengine. use on your own risk.'}
],
    close: function() { this.value = "";},
    select: function(Event, ui) {
        addPolicy(encodeURIComponent(getDN(this)), 'cfPolicy', 'policyClass', ui.item.value);
    }
};


var ac_detail_classes = {
    minLength : 0,
    delay : 0,
    source : [],
    close : function() { this.value = "";},
    select : function(event, ui) {
        var id = encodeURIComponent(getDN(this));
        $.ajax({
            type:'POST', 
            url:'/domad/node/' + id,
            data: {action:'add', attribute:'udGroup', value:ui.item.value}})
         .success(function() {
            $.ajax({type:'GET', url:'/domad/node/' + id, dataType:'xml', success:show_details });
         });
    }
};

/*** tree operations ***/
// save closed nodes.
function toggled_tree_node() {
    var closed_nodes = [];
    if (document.cookie.search(/cn=([^;]+)/) != -1) {
        closed_nodes = JSON.parse(decodeURIComponent(RegExp.$1));
    }
    var n = this.previousSibling.id;
    var i = closed_nodes.indexOf(n);
    if (this.style.display == 'none') {
        if (i==-1) {
            closed_nodes.push(n);
        }
    } else {
        if (i!=-1) {
            closed_nodes.splice(i,1);
        }
    }
    var date = new Date(); 
    date.setTime(date.getTime()+(10*24*60*60*1000));
    document.cookie = 'cn=' + encodeURIComponent(JSON.stringify(closed_nodes)) + '; expires=' + date.toGMTString() + ';'
}

// load tree.xsl at start.
// This triggers loading of the node tree.
$.get("tree.xsl").success(function (r) { 
    tree_xslt_processor.importStylesheet(r); 
    // now its safe to load the tree.
    $.get('/domad/home', false, false, 'json').success( function(homes) {
        for (var i=0; i < homes.length; i++)
            $.get('/domad/childs/'+encodeURIComponent(homes[i]), false,false,'xml').success(display_tree);
    })
});
// If the user clicks on a item in the tree before this import is processed, we fail.
// However, the user already loaded tree.xsl and at least one node tree, so unlikely to happen.
// Worst case is the user does not get any information while wait for the xsl to load.
$.get("node.xsl").success(function (r) { detail_xslt_processor.importStylesheet(r); });

// define what can receive ud items
var droppers = '.ou, .udhost, .udhostcontainer, .udgroup';
// define what can be moved around
var droppables = '.uddomain, .ou, .udhostcontainer';
// add/replace a node tree 
function display_tree(xml_tree) {
    var tree = tree_xslt_processor.transformToFragment(xml_tree, document);
    var tree_name = tree.firstChild.children[0].children[1].textContent;
    var tree_dn = tree.firstChild.getAttribute('dn');
    // check if this is a reload if so skip all the sorting stuff and replace the node
    var old_tree = $('#tree [dn="'+tree_dn+'"]');
    if (old_tree.length > 0) {
        old_tree.replaceWith(tree);
    } else {
        var current_trees_names = $('#tree > li > div > span');
        var current_trees_count = current_trees_names.length;
        var next_node = 0;
    
        // the single trees come in async, so the order is always different.
        // we avoid confusion by simple sorting.
        while ( next_node < current_trees_count && current_trees_names[next_node].textContent < tree_name)
            next_node++;
        if ( next_node < current_trees_count) 
            // nth-node is 1-based indexed and we never use next_node again.
            $('#tree > li:nth-of-type('+(++next_node)+')').before(tree);
        else
            $('#tree').append(tree);
    }    
    // reset tree to the DOM elemtn in use. The original tree document is empty and of no use.
    tree = $('#tree [dn$="'+tree_dn+'"]');
    // drag and drop
    tree.find('div').draggable({ helper: 'clone', revert: 'invalid' });
    tree.find(droppables).find('span').droppable({ accept: droppers, hoverClass: 'drag_targeted', drop: drop_node });
    // show details (double click behaves weird on mobile devices, so we use single click for now)
    tree.find('span').click(open_node);
    // action menu 
    tree.find('button').button({ icons: { primary: 'ui-icon-triangle-1-s'}, text:false}).click(treeMenu);
    // show/hide subtree
    tree.find('img').click(toggle_node);

    // setup search
    ac_tree_search.source = $.makeArray($('#tree li > div > span').map(function(i,o) {return { label: o.textContent, value: ''};}));
    ac_detail_classes.source = $.makeArray($('#tree .udgroup > span').map(function(i,o) { return o.textContent; }));
    $('#tree_search input').autocomplete(ac_tree_search);
    $('#tree_search input')[0].value = '';

    // close all previously closed nodes.
    if (document.cookie.search(/cn=([^;]+)/) != -1) {
        var closed_nodes = JSON.parse(decodeURIComponent(RegExp.$1));
        for (var i=0; i < closed_nodes.length; i++) {
            $('[dn="'+closed_nodes[i]+'"] > ul').css('display', 'none');
        }
    }
}
// move around item in the tree
function drop_node(event, item) {
    var p = getDN(item.draggable[0]);
    var s = getDN(this);
    $.ajax('/domad/childs/' + encodeURIComponent(p), {
        data: p.split(',',1)[0] + ',' + s, 
        type: 'POST',
        p : p.substr(p.indexOf(',')+1),
        s : s,
        error: function (xhr) { alert(xhr.responseText); },
        complete: function (xhr) {
            $.get('/domad/childs/'+encodeURIComponent(this.p), false,false,'xml').success(display_tree);
            $.get('/domad/childs/'+encodeURIComponent(this.s), false,false,'xml').success(display_tree);
        }});
}
// user doublcklicked a tree object. load it.
function open_node(event) {
    $.get('/domad/node/' + encodeURIComponent(getDN(this)), false, false, 'xml')
     .error(function (xhr) { alert(xhr.responseText); })
     .success( show_details );   
}
// show/hide a subtree and save status in a cookie
function toggle_node(event) {
    $(this).parent().siblings('ul').slideToggle('fast', save_state);
}
function save_state() {
    var date = new Date();
    date.setTime(date.getTime()+(10*24*60*60*1000));
    document.cookie = 'cn='
                    + encodeURIComponent(JSON.stringify(
                        $.makeArray($('ul')
                         .filter(function(i) { return $(this).css('display') === 'none'})
                         .parentsUntil('ul')
                         .map(function(i,o) { return o.getAttribute('dn')}))))
                    + '; expires=' + date.toGMTString() + ';'
}
// open tree menu
function treeMenu() {
    var input = $(this).autocomplete(ac_tree_context);
    if (input.autocomplete("widget").is(":visible")) {
        input.autocomplete("close");
        return ;
    }
    input.autocomplete("search","");
    input.focus();
};

/*** detail tab setup ***/
var node_policy_opened = {};
function open_policy(a,b,c) {
    $(this).siblings('table').fadeIn(); 
    $(this.parentNode).children('img').toggleClass('hidden');
    var dn = getDN(this);
    var pol = $(this).siblings('span')[0].textContent;
    if (node_policy_opened[dn] == undefined) {
        node_policy_opened[dn] = [];
    }
    if (node_policy_opened[dn].indexOf(pol) == -1) {
        node_policy_opened[dn].push(pol);
    }
}
function close_policy(a,b,c) {
    $(this).siblings('table').fadeOut(); 
    $(this.parentNode).children('img').toggleClass('hidden');
    var dn = getDN(this);
    var pol = $(this).siblings('span')[0].textContent;
    if (node_policy_opened[dn] != undefined) {
        for (var i = 0; i < node_policy_opened[dn].length; i++) {
            if (node_policy_opened[dn][i] == pol) {
                node_policy_opened[dn].splice(i,1);
            }
        }
    }
}
// we got detail data from server
function show_details(node) {
    // create tab if not already done.
    if ($('#details .ui-tabs-nav').length == 0) $(function () { $('#details').tabs(); });
    var detail = detail_xslt_processor.transformToFragment(node, document);
    var id = detail.firstChild.id;
    var dn = detail.firstChild.getAttribute('dn');
    var name = '<span title="' + dn + '">' +  detail.firstChild.getAttribute('shortname') + '</span>';
    // TODO: replace instead add so we don't mess with the order of the tabs
    if ($('#' + id).length > 0) {
        $('#details').tabs('remove', '#'+id);
    }
    $('#details').append(detail);
    $('#details').tabs('add', '#' + id, name + '<img src="images/cancel.png" onclick="close_node(this.parentNode.parentNode.href)"/>');

    //setup autocomplete
    // classes
    $('#' + id + " input[name='classes']").autocomplete(ac_detail_classes);
    // uid
    $('#' + id + " input[name='uid']").autocomplete(ac_detail_user);
    $('#' + id + " .userPolicy input[name='uid']").autocomplete({select: function(event, ui) {
        addPolicy(encodeURIComponent(getDN(this)), 'userPolicy', 'uid', ui.item.value);}});
    $('#' + id + " .sudoPolicy input[name='uid']").autocomplete({select: function(event, ui) {
        addPolicy(encodeURIComponent(getDN(this)), 'sudoPolicy', 'uid', ui.item.value);}});
    // gid
    $('#' + id + " .groupPolicy input[name='gid']").autocomplete(ac_detail_group);
    $('#' + id + " .policy_tab:not(.groupPolicy) input[name='gid']").autocomplete(ac_detail_group_with_members);
    $('#' + id + " .userPolicy input[name='gid']").autocomplete({select: function(event, ui) {
        addPolicy(encodeURIComponent(getDN(this)), 'userPolicy', 'unixGroup', ui.item.value);}});
    $('#' + id + " .groupPolicy input[name='gid']").autocomplete({select: function(event, ui) {
        addPolicy(encodeURIComponent(getDN(this)), 'groupPolicy', 'unixGroup', ui.item.value);}});
    $('#' + id + " .sudoPolicy input[name='gid']").autocomplete({select: function(event, ui) {
        addPolicy(encodeURIComponent(getDN(this)), 'sudoPolicy', 'unixGroup', ui.item.value);}});
    // cfpol
    $('#' + id + " .cfPolicy input[name='cfpol']").autocomplete(ac_detail_policy);
    $('#' + id + " .cfPolicy input[name='fcpol']").change(function() {
        addPolicy(encodeURIComponent(getDN(this)), 'cfPolicy', 'policyClass', this.value);
        this.value = ""; });
    // localhome
    //$('#' + id + " input[name='localhome']").change(function(event, a,b,c) { console.log(this, event, a,b,c);});
    // disabled user data
    $('#' + id + " input[name='disable']").autocomplete(ac_detail_user);
    $('#' + id + " .userPolicy input[name='disable']").autocomplete({select: function(event,ui) {
        addPolicy(encodeURIComponent(getDN(this)), 'userPolicy', 'disabledPolicyData', ui.item.value);}});
    $('#' + id + " .sudoPolicy input[name='disable']").autocomplete({select: function(event,ui) {
        addPolicy(encodeURIComponent(getDN(this)), 'sudoPolicy', 'disabledPolicyData', ui.item.value);}});
    $('#' + id + " .localHomePolicy input[name='disable']").autocomplete({select: function(event,ui) {
        addPolicy(encodeURIComponent(getDN(this)), 'localHomePolicy', 'disabledPolicyData', ui.item.value);}});

    // auto open preseeded fields
    $('#' + id + " input[name='gid']").focus(function() { $(this).autocomplete('search') });
    $('#' + id + " input[name='cfpol']").focus(function() { $(this).autocomplete('search') });
    $('#' + id + " input[name='classes']").focus(function() { $(this).autocomplete('search') });


    // set this tab as the currently active tab.
    $('#details').tabs('select', '#' + id);
    // setup open/close policy
    $('#' + id + " img[src='images/indicator.png']").click(open_policy);
    $('#' + id + " img[src='images/open_indicator.png']").click(close_policy);
    // restore close state
    if (node_policy_opened[dn] != undefined) {
        for (var i = 0; i < node_policy_opened[dn].length; i++) {
            var tab = $('#' + id + " ." + node_policy_opened[dn][i]);
            tab.children('table').css('display', 'table');
            tab.children('img').toggleClass('hidden');
        }
    }
}
//close a node tab
function close_node(link) {
    $('#details').tabs('remove', link.replace(/^[^#]+/,''));
}


// node specific function
function addDescription(node) {
    var id = encodeURIComponent(getDN(node));
    var description = prompt('Add a description');
    if (description) {
        $.ajax({
            type: 'POST',
            url: '/domad/node/' + id,
            data: {action:'add', attribute:'description', value:description},
            success: function() {
                $.ajax({type:'GET', url:'/domad/node/' + id, dataType:'xml', success:show_details });
            }
        });
    }
}

function editDescription(node) {
    var id = encodeURIComponent(getDN(node));
    var oldd = node.parentNode.previousSibling.textContent;
    var newd = prompt('Edit the description', oldd);
    if (newd && newd != oldd) {
        $.ajax({ 
            type: 'POST',
            url: '/domad/node/' + id,
            data: {action:'change', attribute:'description', oldValue:oldd, newValue:newd},
            success: function() {
                $.ajax({type:'GET', url:'/domad/node/' + id, dataType:'xml', success:show_details });
             }
        });
    }
}
function deleteDescription(node) {
    var id = encodeURIComponent(getDN(node));
    $.ajax({
        type: 'POST',
        url: '/domad/node/' + id,
        data: {action:'delete', attribute:'description', value:node.parentNode.previousSibling.textContent},
        success: function() {
            $.ajax({type:'GET', url:'/domad/node/' + id, dataType:'xml', success:show_details });
        }
    });
}

function addLocalHomePolicy(node) {
    var id = encodeURIComponent(getDN(node));
    var path = prompt('Specify the base path for the home directories\nMUST start with a /');
    if (path) {
        addPolicy(id, 'localHomePolicy', 'customPolicyData', path);
    }
}
function editLocalHomePolicy(node) {
    var id = encodeURIComponent(getDN(node));
    var oldpath = node.parentNode.previousSibling.textContent;
    var newpath = prompt('Change the path for the home directories\nMUST start with a /', oldpath);
    if (newpath && oldpath != newpath) {
        $.ajax({type:'POST', url:'/domad/node/' + id, data: {action:'deletePol', policy:'localHomePolicy', attribute:'customPolicyData', value:oldpath}})
         .success(function() { addPolicy(id, 'localHomePolicy', 'customPolicyData', newpath)});
    }
}



// helpers for policy handling
function addPolicy(id, pol, att, val) {
    $.ajax({type:'POST', url:'/domad/node/' + id, data: {action:'addPol', policy:pol, attribute:att, value:val}})
     .success(function() {
        $.ajax({type:'GET', url:'/domad/node/' + id, dataType:'xml', success:show_details });
     });
}
function removePolicy(id, pol, att, val) {
    $.ajax({type:'POST', url:'/domad/node/' + id, data: {action:'deletePol', policy:pol, attribute:att, value:val}})
     .success(function() {
        $.ajax({type:'GET', url:'/domad/node/' + id, dataType:'xml', success:show_details});
     });
}

/* get the dn for the node given.
 * goes up the dom tree and loosk for the first object with a dn attribute.
 * most usefull inside the details tab.
 */ 
function getDN(dom) {
    while (!dom.getAttribute('dn') && dom.parentNode )
        dom = dom.parentNode;
    return dom.getAttribute('dn') ? dom.getAttribute('dn') : false;
}
