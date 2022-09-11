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

function updateAnalysisTable(analysisTag){
    if(active_profile && active_timewindow){
        let link = "/analysis/" + active_hotkey_name + "/" + active_profile + "/" + active_timewindow
        $("#table_"+analysisTag).DataTable().ajax.url(link).load();
        switch(analysisTag){
            case "timeline": {
                initializeTimelineListeners()
                break;
            }
            case "timeline_flows": {
                initializeTimelineFlowsListeners()
                break;
            }
        }
    }
    document.getElementById(active_hotkey_name).style.display = "block"
}

function hideAnalysisTable() {
    document.getElementById(last_active_hotkey_name).style.display = "none"
    last_active_hotkey_name = active_hotkey_name;
}

function updateIPInfo(row, field){
    let data = row.data();
    let url = '/analysis/info/' + data[field];
    $("#table_ipinfo").DataTable().ajax.url(url).load();
        console.log(data[field], url)

}

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

function addTableTWs(tableID) {
    let entry ='<table' + ' id="'+ tableID + '"' + ' class="table table-striped" >'
    let exit = '</table>'
    let head ="<thead>"+
     "<tr>"+
     "<th>TW</th>" +
     "</tr>"+
     "</thead>"
    return (entry + head  + exit);
};

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
        hideAnalysisTable()
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
        hideAnalysisTable()
    }
}

function convertDotToDash(string){
    return string.replace(/\./g,'_');
}

/* EVENTS */
$("#buttons .btn").click(function () {
    $("#buttons .btn").removeClass('active');
    $(this).toggleClass('active');
    let [first, ...rest] = (this.id).split('_');
    active_hotkey_name = rest.join('_');
    if (active_hotkey_name != last_active_hotkey_name) {
        hideAnalysisTable();
    }
   updateAnalysisTable(active_hotkey_name)
});

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
function initializeTimelineFlowsListeners(){
    $('#table_timeline_flows').on('click', 'tbody td.saddr', function () {
        let row = $("#table_timeline_flows").DataTable().row($(this).parents('tr'));
        updateIPInfo(row, "saddr")
    })

    $('#table_timeline_flows').on('click', 'tbody td.daddr', function () {
        let row = $("#table_timeline_flows").DataTable().row($(this).parents('tr'));
        updateIPInfo(row, "daddr")
    })
}

function removeListeners(){
     $("#table_timeline").off("click", "**")
}
function initializeTimelineListeners(){
    $('#table_timeline').on('click', 'tbody td.daddr', function () {
        let row = $("#table_timeline").DataTable().row($(this).parents('tr'));
        updateIPInfo(row, "daddr")
    })

    $('#table_timeline_filter_button').click(function(){
        var filter_gender = $('#table_timeline_filter_input').val();
        if(filter_gender != ''){hotkeys.search_reload(filter_gender);}
        else{hotkeys.search_reload(filter_gender);}
    });
}
$('#table_alerts').on('click', 'tbody td.r', function () {
    var tr = $(this).closest('tr');
    var row = $("#table_alerts").DataTable().row(tr);
    if (row.child.isShown()) {
        row.child.hide();
        tr.removeClass('shown');
    } else {
        row.child(add_table_evidence(row.data())).show();
        let table_id = "#" + row.data()["alert_id"]
        let evidence = $(table_id).DataTable(analysisSubTableDefs["evidence"]);
        let link = "/analysis/evidence/" + active_profile + "/" + active_timewindow + "/" + row.data()["alert_id"]
        evidence.ajax.url(link).load();
        tr.addClass('shown');
    }
});


$(document).ready(function() {
    initAnalysisTables()
});

document.onkeydown = KeyPress;