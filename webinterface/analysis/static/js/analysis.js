import { analysisTableDefs, analysisSubTableDefs } from "./tableDefs.js"

let active_profile = '';
let active_timewindow = '';
let active_timewindow_index = 0;
let active_tw_id = "";
let active_hotkey_name = 'timeline';
let last_active_hotkey_name = 'timeline';
let active_hotkey_table = null;


function initAnalysisTables(){
    for (const [key, value] of Object.entries(analysisTableDefs)) {
        $("#table_" + key).DataTable(value);
    }
}

 let operate_hotkeys = function () {



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
function convertDotToDash(string){
    return string.replace(/\./g,'_');
}
    }
function addTableTWsListener(table_tw_id,tr){
    $("#" + table_tw_id).on('click', 'tbody tr', function () {
        let row = $("#" + table_tw_id).DataTable().row($(this))
        let rowData = row.data();
        let rowIndex = row.index();
        let t = $("#" + table_tw_id).DataTable();
        if(active_tw_id){
          $($(active_tw_id).DataTable().row(active_timewindow_index).node()).removeClass('row_selected');

        }
        active_tw_id = "#" + table_tw_id
        active_timewindow_index = rowIndex;
        $(t.row(rowIndex).node()).addClass('row_selected');
        active_profile =  $("#table_profiles").DataTable().row(tr).data()["profile"]
        active_timewindow = rowData["tw"]
        document.getElementById("active_profile_tw").innerText = "Selected: " + active_profile + " " + rowData["name"];
        updateAnalysisTable(active_hotkey_name)
     });
}

$('#table_profiles').on('click', 'tbody td.r', function () {
    let tr = $(this).closest('tr');
    let row = $("#table_profiles").DataTable().row(tr);
    updateIPInfo(row, "profile")

    let profile_id = row.data()['profile']
    let profile_id_dash = convertDotToDash(profile_id)

    if (row.child.isShown()) {
        $("#" + profile_id_dash).DataTable().clear().destroy();
        row.child.hide();
        tr.removeClass('shown');
    }
    else {
        row.child(addTableTWs(profile_id_dash)).show();
        let url = '/analysis/tws/' + profile_id;
        let table_tws = $("#" + profile_id_dash).DataTable(analysisSubTableDefs["tw"]);
        table_tws.ajax.url(url).load();
        addTableTWsListener(profile_id_dash, tr)
        tr.addClass('shown');
    }
});
document.onkeydown = KeyPress;