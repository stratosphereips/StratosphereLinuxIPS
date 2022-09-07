
const custom_dom = "<'row'<'col-lg-8 col-md-8 col-xs-12'B><'col-lg-4 col-md-4 col-xs-12'fl>>" +
           "<'row'<'col-sm-12'tr>>" +
           "<'row'<'col-sm-12 col-md-5'i><'col-sm-12 col-md-7'p>>"

let active_profile = '';
let active_timewindow = '';
let active_timewindow_index = 0;
let active_tw_id = "";
let active_hotkey_name = 'timeline';
let last_active_hotkey_name = 'timeline';
let active_hotkey_table = null;


/*
Set profile and timewindow table.
Functions:
    onclick_tws:
    onclick_ips: display a list of timewindows onclick, and the IP info
*/
let profiles = function () {
    let profiles_table = $('#profiles').DataTable({
        destroy: true,
        dom: '<"top"f>rt',
        scrollX: false,
        scrollY: "78vh", // hardcoded height to fit the page
        scrollCollapse: true,
        paging:false,
        info: false,
        ajax: '/analysis/profiles_tws',
        columns: [
            {
                data: 'profile',
                "className": 'r'
            }
        ],
        fnRowCallback: function( nRow, aData, iDisplayIndex, iDisplayIndexFull ) {
            switch(aData['blocked']){
                case true:
                    $('td', nRow).css('background-color', '#FF8989')
                    break;
            }
        }
    });


    function add_table_tws(table_id) {
        let entry ='<table' + ' id="'+ table_id + '"' + ' class="table table-striped" >'
        let exit = '</table>'
        let head ="<thead>"+
         "<tr>"+
         "<th>TW</th>" +
         "</tr>"+
         "</thead>"
        return (entry + head  + exit);
    };

    var convertDotToDash = function(string) {
        return string.replace(/\./g,'_');
    }


    return {
        onclick_tws: function () {
            $('#profiles').on('click', 'tbody td.r', function () {
                let tr = $(this).closest('tr');
                let row = profiles_table.row(tr);

                let profile_id = row.data()['profile']
                let profile_id_dash = convertDotToDash(profile_id)
                let table_id_tw = '#' + profile_id_dash

                if (row.child.isShown()) {
                    $(table_id_tw).DataTable().clear().destroy();
                    row.child.hide();
                    tr.removeClass('shown');
                }
                else {
                    row.child(add_table_tws(profile_id_dash)).show();
                    let ajax_ljnk = '/analysis/tws/' + profile_id;
                    let table_tws = $(table_id_tw).DataTable({
                        "ajax":ajax_ljnk,
                        "bDestroy": true,
                        dom: custom_dom,
                        bInfo: false,
                        ordering: false,
                        paging: false,
                        searching: false,
                        columns: [
                            {data: 'name'}
                        ],
                        fnRowCallback: function( nRow, aData, iDisplayIndex, iDisplayIndexFull ) {
                            switch(aData['blocked']){
                                case true:
                                    $('td', nRow).css('background-color', '#FF8989')
                                    break;
                            }
                        }
                    });

                    $(table_id_tw).on('click', 'tbody tr', function () {
                        let row = table_tws.row($(this))
                        let rowData = row.data();
                        let rowIndex = row.index();
                        let t = $(table_id_tw).DataTable();
                        if(active_tw_id){
                          $($(active_tw_id).DataTable().row(active_timewindow_index).node()).removeClass('row_selected');

                        }
                        active_tw_id = table_id_tw
                        active_timewindow_index = rowIndex;
                        $(t.row(rowIndex).node()).addClass('row_selected');
                        active_profile =  profiles_table.row(tr).data()["profile"]
                        active_timewindow = rowData["tw"]
                        document.getElementById("active_profile_tw").innerText = "Selected: " + active_profile + " " + rowData["name"];
                        hotkey_hook.initialize_profile_timewindow()
                     });

                    tr.addClass('shown');
                }
            });
        },

        onclick_ips: function () {
            $('#profiles ').on('click', 'tbody td.r', function () {
                let data = profiles_table.row($(this).parents('tr')).data();
                let url = '/analysis/info/' + data.profile
                ipinfo.ajax.url(url).load();
            });
        },

        get_profiles_table: function(){
            return profiles_table;
        }

    }
}

 let operate_hotkeys = function () {

    let timeline_flows = $('#table_timeline_flows').DataTable({
        destroy: true,
        dom: custom_dom,
        buttons: ['colvis'],
        scrollX: true,
        columns: [
            { data: 'ts' },
            { data: 'dur' },
            { data: 'saddr' ,
              "className": 'saddr'},
            { data: 'sport' },
            { data: 'daddr' ,
            "className": 'daddr'},
            { data: 'dport' },
            { data: 'proto' },
            { data: 'origstate' },
            { data: 'state' },
            { data: 'pkts' },
            { data: 'allbytes' },
            { data: 'spkts' },
            { data: 'sbytes' }
        ]
    });

    let timeline = $('#table_timeline').DataTable({
        destroy: true,
        dom: custom_dom,
        buttons: ['colvis'],
        scrollX: true,
        searching: false,
        columns: [
            { data: 'timestamp' },
            { data: 'dport_name' },
            { data: 'preposition' },
            { data: 'daddr',
            "className": 'daddr'},
            { data: 'dns_resolution' },
            { data: 'dport/proto' },
            { data: 'state' },
            { data: 'Sent' },
            { data: 'Recv' },
            { data: 'Tot' },
            { data: 'Duration' },
            { data: 'warning' },
            { data: 'critical warning' },
            { data: 'info' }
        ]
    });

    let outtuples = $('#table_outtuples').DataTable({
        destroy: true,
        dom: custom_dom,
        buttons: ['colvis'],
        scrollX: true,
        columns: [
            { data: 'tuple' },
            { data: 'string' },
            { data: 'geocountry' },
            { data: 'reverse_dns' },
            { data: 'asnorg' },
            { data: 'threat_intel' },
            { data: 'url' },
            { data: 'down_file' },
            { data: 'ref_file' },
            { data: 'com_file' }
        ]
    });

    let intuples = $('#table_intuples').DataTable({
        destroy: true,
        dom: custom_dom,
        buttons: ['colvis'],
        scrollX: true,
        columns: [
            { data: 'tuple' },
            { data: 'string' },
            { data: 'geocountry' },
            { data: 'reverse_dns' },
            { data: 'asnorg' },
            { data: 'threat_intel' },
            { data: 'url' },
            { data: 'down_file' },
            { data: 'ref_file' },
            { data: 'com_file' }
        ]
    });

    let alerts = $('#table_alerts').DataTable({
        "bDestroy": true,
        select: true,
        dom: custom_dom,
        scrollX: false,
        columns: [
            { data: 'alert' ,
            "className":"r"},
            { data: 'profileid'},
            { data: 'timewindow'},
            { data: 'evidence_count'}

        ]
    });


    function add_table_evidence(d) {
        let table_id = d["alert_id"]
        let entry ='<table' + ' id="'+ table_id + '"' + 'class="table table-striped" cellpadding="5" cellspacing="0" border="0" style="padding-left:50px;">'
        let exit = '</table>'
        let head ="<thead>"+
         "<tr>"+
         "<th>Evidence</th>" +
         "<th>Confidence</th>" +
         "<th>Threat Level</th>" +
         "<th>Category</th>" +
          "<th>Tag</th>" +
         "<th>Description</th>" +
         "</tr>"+
         "</thead>"
        return (entry + head  + exit);
    }

    function hide_hotkey() {
        document.getElementById(last_active_hotkey_name).style.display = "none"
        last_active_hotkey_name = active_hotkey_name;
    }

    function update_table(){
        if(active_profile && active_timewindow){
            let link = "/analysis/" + active_hotkey_name + "/" + active_profile + "/" + active_timewindow
            active_hotkey_table.ajax.url(link).load();}
        document.getElementById(active_hotkey_name).style.display = "block"
    }

    function update_hotkey(){
        switch (active_hotkey_name) {
            case 'timeline':
                active_hotkey_table = timeline
                update_table()
                break;
            case 'timeline_flows':
                active_hotkey_table = timeline_flows
                update_table()
                break;
            case 'outtuples':
                active_hotkey_table = outtuples
                update_table()
                break;
            case 'intuples':
                active_hotkey_table = intuples
                update_table()
                break;
            case 'alerts':
                active_hotkey_table = alerts
                update_table()
                break;
        }
    }

    return {

        update_hook: function(){
            update_hotkey()
        },

        search_reload: function(filter_parameter){
           let link = "/analysis/" + active_hotkey_name + "/" + profile + "/" + timewindow
            if (filter_parameter){ link += "/" + filter_parameter; }
            active_hotkey_table.ajax.url(link).load();
        },

        onclick_buttons: function () {
            $("#buttons .btn").click(function () {
                $("#buttons .btn").removeClass('active');
                $(this).toggleClass('active');
                let [first, ...rest] = (this.id).split('_');
                active_hotkey_name = rest.join('_');
                if (active_hotkey_name != last_active_hotkey_name) {
                    hide_hotkey();
                }
               update_hotkey()
            });
        },

        onclick_timeline_flows_saddr: function () {
        $('#table_timeline_flows ').on('click', 'tbody td.saddr', function () {
                let data = timeline_flows.row($(this).parents('tr')).data();
                let url = '/analysis/info/' + data.saddr;
                ipinfo.ajax.url(url).load();
            })
        },

        onclick_timeline_flows_daddr: function () {
        $('#table_timeline_flows ').on('click', 'tbody td.daddr', function () {
                let data = timeline_flows.row($(this).parents('tr')).data();
                let url = '/analysis/info/' + data.daddr;
                ipinfo.ajax.url(url).load();
            })
        },

        onclick_timeline_daddr: function () {
        $('#table_timeline ').on('click', 'tbody td.daddr', function () {
                let data = timeline.row($(this).parents('tr')).data();
                let url = '/analysis/info/' + data.daddr;
                ipinfo.ajax.url(url).load();
            })
        },

        onclick_alerts: function () {
            $('#table_alerts ').on('click', 'tbody td.r', function () {
                var tr = $(this).closest('tr');
                var row = alerts.row(tr);
                if (row.child.isShown()) {
                    row.child.hide();
                    tr.removeClass('shown');
                } else {
                    row.child(add_table_evidence(row.data())).show();
                    let table_id = "#" + row.data()["alert_id"]
                    let evidence = $(table_id).DataTable({
                        "bDestroy": true,
                        dom: custom_dom,
                        bInfo: false,
                        paging: false,
                        searching: false,
                        scrollY: "25vh", // hardcoded length of opened datatable
                        columns: [
                            { data: 'stime'},
                            { data: 'confidence'},
                            { data: 'threat_level'},
                            { data: 'category'},
                            { data: 'source_target_tag'},
                            { data: 'description'}
                        ]
                    });
                    let link = "/analysis/evidence/" + active_profile + "/" + active_timewindow + "/" + row.data()["alert_id"]
                    evidence.ajax.url(link).load();
                    tr.addClass('shown');
                }
            });
        }
    }
}

let ipinfo = $('#ipinfo').DataTable({
    "bDestroy": true,
    ordering: false,
    searching: false,
    "paging": false,
    "bInfo": false,
    responsive: true,
    columns: [
        { data: 'ip' },
        { data: 'geocountry' },
        { data: 'reverse_dns' },
        { data: 'asnorg' },
        { data: 'threat_intel' },
        { data: 'url' },
        { data: 'down_file' },
        { data: 'ref_file' },
        { data: 'com_file' }
    ]
});


let profile_handle = profiles();
profile_handle.onclick_tws();
profile_handle.onclick_ips();

let hotkeys = operate_hotkeys();
hotkeys.onclick_buttons();
hotkeys.onclick_timeline_flows_saddr();
hotkeys.onclick_timeline_flows_daddr();
hotkeys.onclick_timeline_daddr();
hotkeys.onclick_alerts();

let hotkey_hook = {
    'initialize_profile_timewindow': function () {
        hotkeys.update_hook();
    }
}

$('#table_timeline_filter_button').click(function(){
    var filter_gender = $('#table_timeline_filter_input').val();
    if(filter_gender != ''){hotkeys.search_reload(filter_gender);}
    else{hotkeys.search_reload(filter_gender);}
});

function updateTable(){
    hotkeys.update_hook()
}


function KeyPress(e) {
    let evtobj = window.event? event : e
    if (evtobj.keyCode == 78 && evtobj.ctrlKey){
        var table = $(active_tw_id).DataTable();
        $(table.row(active_timewindow_index).node()).removeClass('row_selected');
        active_timewindow_index += 1
        if(active_timewindow_index == table.data().count() - 1){
            active_timewindow_index = 0
        }
        $(table.row(active_timewindow_index).node()).addClass('row_selected');
        active_timewindow = table.row(active_timewindow_index).data()["tw"]
        updateTable()
    }
    if (evtobj.keyCode == 80 && evtobj.ctrlKey){
        var table = $(active_tw_id).DataTable();
        $(table.row(active_timewindow_index).node()).removeClass('row_selected');
        active_timewindow_index -= 1;
        if(active_timewindow_index < 0){
            active_timewindow_index = table.data().count() - 1;
        }
        $(table.row(active_timewindow_index).node()).addClass('row_selected');
        active_timewindow = table.row(active_timewindow_index).data()["tw"]
        updateTable()
    }
}

document.onkeydown = KeyPress;