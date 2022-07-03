/*
Set profile and timewindow table.
Functions:
    onclick_tws:
    onclick_ips: display a list of timewindows onclick, and the IP info
*/
let profiles = function () {
    let profiles_table = $('#profiles').DataTable({
        ajax: '/hotkeys/profiles_tws',
        serverSide: true,
        "scrollY":  true,
        "scrollCollapse": true,
        "paging": false,
        "bInfo": false,
        ordering: false,
        searching: false,
        "rowId": 'id',
        columns: [
            {
                data: 'profile',
                "className": 'r'
            }
        ],
        "fnRowCallback": function( nRow, aData, iDisplayIndex, iDisplayIndexFull ) {
            switch(aData['blocked']){
                case true:
                    $('td', nRow).css('background-color', '#FF8989')
                    break;
            }
    }
    });
    return {
        onclick_tws: function () {
            function add_tws(profile_tws) {
                const open_string = '<table class="table table-striped">'
                const close_string = '</table>'
                let data = ""
                Object.entries(profile_tws.tws).forEach(([item, value]) => {
                let colored_item = ""
                    if(value){
                       colored_item = '<td style="background-color:#FF8989">' + item + '</td>'
                    }
                    else{
                       colored_item = '<td style="background-color:#FFFFFF">' + item + '</td>'
                    }
                    data = data + '<tr onclick="hotkey_hook.initialize_profile_timewindow(' + "'" + "profile_" + profile_tws.profile + "'" + ',' + "'" + item + "'" + ')">' + colored_item + '</tr>';
                })
                return open_string + data + close_string;
            }

            $('#profiles').on('click', 'tbody td.r', function () {
                let tr = $(this).closest('tr');
                let row = profiles_table.row(tr);
                if (row.child.isShown()) {
                    row.child.hide();
                }
                else {
                    row.child(add_tws(row.data())).show();
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

let profile = profiles();
profile.onclick_tws();
profile.onclick_ips();

 let operate_hotkeys = function () {
    let profile = '';
    let timewindow = '';
    let active_hotkey_name = 'timeline';
    let last_active_hotkey_name = 'timeline';
    let active_hotkey_table = null

    let timeline_flows = $('#table_timeline_flows').DataTable({
        'dom': 'Rlfrtip',
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
        "bDestroy": true,
        'dom': 'Rlfrtip',
        scrollX: true,
        columns: [
            { data: 'timestamp' },
            { data: 'dport_name' },
            { data: 'dns_resolution' },
            { data: 'daddr' },
            { data: 'preposition' },
            { data: 'dport/proto' },
            { data: 'state' },
            { data: 'warning' },
            { data: 'Sent' },
            { data: 'Recv' },
            { data: 'Tot' },
            { data: 'Duration' },
            { data: 'critical warning' },
            { data: 'info' }
        ]
    });

    let outtuples = $('#table_outtuples').DataTable({
        "bDestroy": true,
        'dom': 'Rlfrtip',
        scrollX: true,
        columns: [
            { data: 'tuple' },
            { data: 'string' },
            { data: 'geocountry' },
            { data: 'reverse_dns' },
            { data: 'asnorg' }
        ]
    });

    let alerts = $('#table_alerts').DataTable({
        "bDestroy": true,
        'dom': 'Rlfrtip',
        scrollX: true,
        columns: [
            { data: 'profileid' },
            { data: 'twid'},
            { data: 'type_detection' },
            { data: 'detection_info'},
            { data: 'type_evidence' },
            { data: 'description'},
            { data: 'stime'},
            { data: 'uid' },
            { data: 'confidence'},
            { data: 'threat_level'},
            { data: 'category' }
        ]
    });



    function addData(chart, labels, dataset) {
        chart.data.labels = labels;
        chart.data.datasets[0] = dataset
        chart.update();
    }

    function addOptions(chart, options) {
        chart.options = options;
        chart.update();
    }



    let dstIP = function(){
        const headers = {
        headers: {'Content-Type': 'application/json'}
    }
        let link = "/hotkeys/" + active_hotkey_name + "/" + profile + "/" + timewindow
        fetch(link, {
            method: "GET",
            headers: headers
            }).then(response => response.json())
            .then(data => {
                const labels = data['data'].map(function(d){ return d['ip']})
                const barGraphData = data['data'].map(function(d){ return d['flow']})
                const data_set = data['data'].map(function(d){ return [d['ip'],d['flow']]})
var chart = Highcharts.chart('container', {
    chart: {
        type: 'bar',
        marginLeft: 150,

    },
    title: {
        text: 'Amount of flows per dstIP'
    },
    xAxis: {
        type: 'category',
        title: {
            text: null
        },
        min: 0,
        max: 4,
        scrollbar: {
            enabled: true
        },
        tickLength: 0
    },
    yAxis: {
        min: 0,
        max: 20,
        title: {
            text: 'Flows',
            align: 'high'
        }
    },
    plotOptions: {
        bar: {
            dataLabels: {
                enabled: true
            }
        }
    },
    legend: {
        enabled: false
    },
    credits: {
        enabled: false
    },

    series: [{
        name: 'Flows',
        data: data_set
    }]
});
});

    document.getElementById(active_hotkey_name).style.display = "block"
    }

    function hide_hotkey() {
        document.getElementById(last_active_hotkey_name).style.display = "none"
        last_active_hotkey_name = active_hotkey_name;
    }

    function update_table(){
        let link = "/hotkeys/" + active_hotkey_name + "/" + profile + "/" + timewindow
        active_hotkey_table.ajax.url(link).load();
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
            case 'alerts':
                active_hotkey_table = alerts
                update_table()
                break;
            case 'dstIP':
                dstIP()
                break;
        }
    }

    return {

        set_profile_timewindow: function (pr, tw) {
            profile = pr;
            timewindow = tw;
        },

        update_hook: function(){
            update_hotkey()
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
                let url = '/hotkeys/info/' + data.saddr
                ipinfo.ajax.url(url).load();
            })
        },

        onclick_timeline_flows_daddr: function () {
        $('#table_timeline_flows ').on('click', 'tbody td.daddr', function () {
                let data = timeline_flows.row($(this).parents('tr')).data();
                let url = '/hotkeys/info/' + data.daddr
                ipinfo.ajax.url(url).load();
            })
        }
    }
}

let ipinfo = $('#ipinfo').DataTable({
    "bDestroy": true,
    ordering: false,
    searching: false,
    "paging": false,
    "bInfo": false,
    columns: [
        { data: 'ip' },
        { data: 'geocountry' },
        { data: 'reverse_dns' },
        { data: 'asnorg' }
    ]
});


let hotkeys = operate_hotkeys();
hotkeys.onclick_buttons();
hotkeys.onclick_timeline_flows_saddr();
hotkeys.onclick_timeline_flows_daddr();


let hotkey_hook = {
    'initialize_profile_timewindow': function (profile, timewindow) {
        hotkeys.set_profile_timewindow(profile, timewindow);
        hotkeys.update_hook();
    }
}


    function filterFunction() {
let chartDom = document.getElementById("container");
let chart = Highcharts.charts[Highcharts.attr(chartDom, 'data-highcharts-chart')]
console.log(chart.series[0])
let input = document.getElementById('myInput'),
            points = chart.series[0].points.options,
            filteredPoint = points.filter(point => point.category == input.value);

      if (filteredPoint.length) {
        let newData = [];
        for (let i in data) {
          newData.push(null)
        }

        newData[filteredPoint[0].index] = filteredPoint[0].y
            newData.push(null) //--- extra null as a workaround for bug

        chart.series[0].update({
          data: newData
        })
      } else {
        chart.series[0].update({
          data: data
        })
      }
      }

