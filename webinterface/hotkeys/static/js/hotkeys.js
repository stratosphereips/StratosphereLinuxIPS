
const custom_dom = "<'row'<'col-lg-8 col-md-8 col-xs-12'B><'col-lg-4 col-md-4 col-xs-12'fl>>" +
           "<'row'<'col-sm-12'tr>>" +
           "<'row'<'col-sm-12 col-md-5'i><'col-sm-12 col-md-7'p>>"


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
        ajax: '/hotkeys/profiles_tws',
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

    return {
        onclick_tws: function () {

            function add_table_tws(profileid) {
                let entry ='<table' + ' id="'+ profileid + '"' + 'class="table table-striped" cellpadding="5" cellspacing="0" border="0" style="padding-left:50px;">'
                let exit = '</table>'
                return (entry  + exit);
            };

            function add_tws(profile_tws) {
                const open_string = '<table class="table table-striped">'
                const close_string = '</table>'
                let data = ""
                Object.entries(profile_tws.tws).forEach(([item, value]) => {
                    let colored_item = ""
                    if(value["blocked"]){
                       colored_item = '<td style="background-color:#FF8989">' + value["name"] + '</td>'
                    }
                    else{
                       colored_item = '<td style="background-color:#FFFFFF">' + value["name"] + '</td>'
                    }
                    data = data + '<tr onclick="hotkey_hook.initialize_profile_timewindow(' + "'" + "profile_" + profile_tws.profile + "'" + ',' + "'" + item + "'" + ',' +"'" + value["name"] +"'" +')">' + colored_item + '</tr>';
                })
                return open_string + data + close_string;
            };

            $('#profiles').on('click', 'tbody td.r', function () {
                let tr = $(this).closest('tr');
                let row = profiles_table.row(tr);
                if (row.child.isShown()) {
                    row.child.hide();
                }
                else {
                    let profileid = row.data()['profile']
                    console.log(profileid)
                    row.child(add_table_tws(profileid)).show();
                    let table_id = "#" + profileid
                    console.log(table_id)

                    let table_tws = $(table_id).DataTable({
                        "bDestroy": true,
                        dom: custom_dom,
                        bInfo: false,
                        paging: false,
                        searching: false,
                        scrollY: "25vh", // hardcoded length of opened datatable
                        columns: [
                            {data: 'tws'}
                        ]
                    });
                    let link = '/hotkeys/profiles_tws'
                    table_tws.ajax.url(link).load();
                    tr.addClass('shown');
                }
            });
        },

        onclick_ips: function () {
            $('#profiles ').on('click', 'tbody td.r', function () {
                let data = profiles_table.row($(this).parents('tr')).data();
                let url = '/hotkeys/info/' + data.profile
                ipinfo.ajax.url(url).load();
            });
        }
    }
}

 let operate_hotkeys = function () {
    let profile = '';
    let timewindow = '';
    let active_hotkey_name = 'timeline';
    let last_active_hotkey_name = 'timeline';
    let active_hotkey_table = null;

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
            { data: 'dns_resolution' },
            { data: 'preposition' },
            { data: 'daddr',
            "className": 'daddr'},
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

// TODO: decide and fix chart
//    function addData(chart, labels, dataset) {
//        chart.data.labels = labels;
//        chart.data.datasets[0] = dataset
//        chart.update();
//    }
//
//    function addOptions(chart, options) {
//        chart.options = options;
//        chart.update();
//    }

// TODO: decide and fix chart
//
//    let dstIP = function(){
//        const headers = {
//        headers: {'Content-Type': 'application/json'}
//    }
//        let link = "/hotkeys/" + active_hotkey_name + "/" + profile + "/" + timewindow
//        fetch(link, {
//            method: "GET",
//            headers: headers
//            }).then(response => response.json())
//            .then(data => {
//                const labels = data['data'].map(function(d){ return d['ip']})
//                const barGraphData = data['data'].map(function(d){ return d['flow']})
//                const data_set = data['data'].map(function(d){ return [d['ip'],d['flow']]})
//var chart = Highcharts.chart('container', {
//    chart: {
//        type: 'bar',
//        marginLeft: 150,
//
//    },
//    title: {
//        text: 'Amount of flows per dstIP'
//    },
//    xAxis: {
//        type: 'category',
//        title: {
//            text: null
//        },
//        min: 0,
//        max: 4,
//        scrollbar: {
//            enabled: true
//        },
//        tickLength: 0
//    },
//    yAxis: {
//        min: 0,
//        max: 20,
//        title: {
//            text: 'Flows',
//            align: 'high'
//        }
//    },
//    plotOptions: {
//        bar: {
//            dataLabels: {
//                enabled: true
//            }
//        }
//    },
//    legend: {
//        enabled: false
//    },
//    credits: {
//        enabled: false
//    },
//
//    series: [{
//        name: 'Flows',
//        data: data_set
//    }]
//});
//});
//
//    document.getElementById(active_hotkey_name).style.display = "block"
//    }

    function hide_hotkey() {
        document.getElementById(last_active_hotkey_name).style.display = "none"
        last_active_hotkey_name = active_hotkey_name;
    }

    function update_table(){
        if(profile && timewindow){
            let link = "/hotkeys/" + active_hotkey_name + "/" + profile + "/" + timewindow
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
                // TODO: decide and fix chart
//            case 'dstIP':
//                dstIP()
//                break;
        }
    }

    return {

        set_profile_timewindow: function (pr, tw, tw_name) {
            profile = pr;
            timewindow = tw;
            document.getElementById("active_profile_tw").innerText = "Selected: " + pr + " " + tw_name;
        },

        update_hook: function(){
            update_hotkey()
        },

        search_reload: function(filter_parameter){
           let link = "/hotkeys/" + active_hotkey_name + "/" + profile + "/" + timewindow
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
                let url = '/hotkeys/info/' + data.saddr;
                ipinfo.ajax.url(url).load();
            })
        },

        onclick_timeline_flows_daddr: function () {
        $('#table_timeline_flows ').on('click', 'tbody td.daddr', function () {
                let data = timeline_flows.row($(this).parents('tr')).data();
                let url = '/hotkeys/info/' + data.daddr;
                ipinfo.ajax.url(url).load();
            })
        },

        onclick_timeline_daddr: function () {
        $('#table_timeline ').on('click', 'tbody td.daddr', function () {
                let data = timeline.row($(this).parents('tr')).data();
                let url = '/hotkeys/info/' + data.daddr;
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
                    let link = "/hotkeys/evidence/" + profile + "/" + timewindow + "/" + row.data()["alert_id"]
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


// TODO: fix the chart filter
//    function filterFunction() {
//        let chartDom = document.getElementById("container");
//        let chart = Highcharts.charts[Highcharts.attr(chartDom, 'data-highcharts-chart')]
//        console.log(chart.series[0])
//        let input = document.getElementById('myInput'),
//                    points = chart.series[0].points.options,
//                    filteredPoint = points.filter(point => point.category == input.value);
//
//              if (filteredPoint.length) {
//                let newData = [];
//                for (let i in data) {
//                  newData.push(null)
//                }
//
//                newData[filteredPoint[0].index] = filteredPoint[0].y
//                    newData.push(null) //--- extra null as a workaround for bug
//
//                chart.series[0].update({
//                  data: newData
//                })
//              } else {
//                chart.series[0].update({
//                  data: data
//                })
//              }
//      }

let profile = profiles();
profile.onclick_tws();
profile.onclick_ips();

let hotkeys = operate_hotkeys();
hotkeys.onclick_buttons();
hotkeys.onclick_timeline_flows_saddr();
hotkeys.onclick_timeline_flows_daddr();
hotkeys.onclick_timeline_daddr();
hotkeys.onclick_alerts();

let hotkey_hook = {
    'initialize_profile_timewindow': function (profile, timewindow, tw_name) {
        hotkeys.set_profile_timewindow(profile, timewindow, tw_name);
        hotkeys.update_hook();
    }
}

$('#table_timeline_filter_button').click(function(){
    var filter_gender = $('#table_timeline_filter_input').val();
    if(filter_gender != ''){hotkeys.search_reload(filter_gender);}
    else{hotkeys.search_reload(filter_gender);}
});
