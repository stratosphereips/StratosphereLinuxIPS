// SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
//SPDX-License-Identifier: GPL-2.0-only
const custom_dom = "<'row'<'col-lg-8 col-md-8 col-xs-12'B><'col-lg-4 col-md-4 col-xs-12'fl>>" +
           "<'row'<'col-sm-12'tr>>" +
           "<'row'<'col-sm-12 col-md-5'i><'col-sm-12 col-md-7'p>>"

let analysisSubTableDefs = {
    "tw":{
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
                    $('td', nRow).css('background-color', '#FFC0CB')
                    break;
            }
        }
    },

    "evidence": {
        "bDestroy": true,
        dom: custom_dom,
        bInfo: false,
        paging: false,
        searching: false,
        scrollY: "25vh", // hardcoded length of opened datatable
        columns: [
            { data: 'timestamp'},
            { data: 'confidence'},
            { data: 'threat_level'},
            { data: 'category'},
            { data: 'source_target_tag'},
            { data: 'description'}
        ]
    }
}


let analysisTableDefs = {
    "timeline": {
        destroy: true,
        dom: custom_dom,
        buttons: ['colvis'],
        scrollX: true,
        searching: true,
        columns: [
            { data: 'timestamp' },
            { data: 'dport_name' },
            { data: 'preposition' },
            { data: 'daddr',
            "className": 'daddr'},
            { data: 'dns_resolution' },
            { data: 'dport/proto' },
            { data: 'state' },
            { data: 'sent' },
            { data: 'recv' },
            { data: 'tot' },
            { data: 'duration' },
            { data: 'warning' },
            { data: 'critical warning' }
        ],
        fnRowCallback: function( nRow, aData, iDisplayIndex, iDisplayIndexFull ) {
            if(aData['info']){
                $('td', nRow).css('background-color', '#c2e2fa')
            }
        }
    },
    "outtuples": {
        destroy: true,
        dom: custom_dom,
        buttons: ['colvis'],
        scrollX: true,
        searching: true,
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
    },

    "intuples": {
        destroy: true,
        dom: custom_dom,
        buttons: ['colvis'],
        searching: true,
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
    },

    "timeline_flows": {
        destroy: true,
        dom: custom_dom,
        buttons: ['colvis'],
        scrollX: true,
        searching: true,
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
    },

    "alerts": {
        "bDestroy": true,
        select: true,
        dom: custom_dom,
        scrollX: false,
        searching: true,
        columns: [
            { data: 'alert' ,
            "className":"r"},
            { data: 'profileid'},
            { data: 'timewindow'},
            { data: 'evidence_count'}

        ]
    },

    "ipinfo": {
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
    },

    "profiles": {
        destroy: true,
        dom: '<"top"f>rt',
        scrollX: false,
        scrollY: "78vh", // hardcoded height to fit the page
        scrollCollapse: true,
        paging: false,
        info: false,
        ajax: '/analysis/profiles_tws',
        columns: [
            {
                data: 'profile',
                "className": 'r',
            },
            {
                data: 'blocked'
            }
        ],
        "aoColumnDefs": [
            { "bSearchable": true, "bVisible": true, "aTargets": [ 0 ] },
            { "bSearchable": true, "bVisible": false, "aTargets": [ 1 ] }
        ],
        fnRowCallback: function( nRow, aData, iDisplayIndex, iDisplayIndexFull ) {
            switch(aData['blocked']){
                case true:
                    $('td', nRow).css('background-color', '#FFC0CB ')
                    break;
            }
        }
    },

    "evidence": {
        "bDestroy": true,
        dom: custom_dom,
        bInfo: false,
        paging: true,
        scrollX: false,
        searching: true,
        columns: [
            { data: 'timestamp'},
            { data: 'confidence'},
            { data: 'threat_level'},
            { data: 'category'},
            { data: 'source_target_tag'},
            { data: 'description'}
        ]
    }
}

export { analysisTableDefs, analysisSubTableDefs };
