// SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
//SPDX-License-Identifier: GPL-2.0-only
// import { update } from './analysis.js';
import {update} from '../analysis/analysis/static/js/analysis.js';


const headers2 = {
    headers: { 'Content-Type': 'application/json' }
}
const csrfToken = document.querySelector('meta[name="csrf-token"]').content;

function round(value, precision) {
    var multiplier = Math.pow(10, precision || 0);
    return Math.round(value * multiplier) / multiplier;
}
function calcDur(analysis_start, analysis_end){
    /*
        Calcuialte duration in seconds
    */
    let start = new Date(analysis_start)
    let end = new Date(analysis_end)
    return round((Date.parse(end)- Date.parse(start)) / 60000, 1).toString() + "s"
}
function fetchDetailedInfo() {
    fetch("/info", {
        method: "GET",
        headers: headers2
    }).then(response => response.json())
        .then(data => {
            document.getElementById("num_profiles").textContent = data['num_profiles'];
            document.getElementById("num_alerts").textContent = data['num_alerts'];
            document.getElementById("dur").textContent = calcDur(data['analysis_start'], data['analysis_end']);
        });
}

async function switchRedisDb(port) {
    /*
        Switch the active Redis DB using a CSRF-protected POST request.
    */
    const response = await fetch(`/db/${port}`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": csrfToken
        },
        credentials: "same-origin"
    });

    if (!response.ok) {
        throw new Error(`Failed to switch Redis DB: ${response.status}`);
    }

    return response.json();
}

function initializeWidgetsAndListeners() {
    const redisModalElement = document.getElementById("modal_choose_redis");
    const redisModal = new bootstrap.Modal(redisModalElement, {
        backdrop: "static",
        keyboard: false
    });

    // Table with the list of databases. TODO: change it to dropdown?
    $("#table_choose_redis").DataTable({
        destroy: true,
        searching: false,
        ajax: '/redis',
        "bInfo": false,
        scrollY: "15vh",
        paging: false,
        select: true,
        columns: [
            { data: 'filename' },
            { data: 'redis_port' }
        ]
    })
    $('#reload_button').click(function(){
        update(); // This one is imported from analysis.js
    })

    $('#changedb_button').click(function (event) {
        event.preventDefault();
        redisModal.show();
    })

    redisModalElement.addEventListener('show.bs.modal', function () {
        $('#table_choose_redis').DataTable().ajax.reload();
    })

    $('#button_choose_db').click(async function () {
        let chosen_db = $('#table_choose_redis').DataTable().row({ selected: true }).data()
        if (!chosen_db) {
            return;
        }

        try {
            await switchRedisDb(chosen_db['redis_port']);
            redisModal.hide();
            window.location.reload();
        } catch (error) {
            console.error(error);
            window.alert("Failed to switch DB. Reload the page and try again.");
        }
    });

}

function setChangeDbButtonLabel(name) {
    /*
        Render the change-db button label without parsing user-controlled HTML.

        Parameters:
            name: Database name to display in the button.

        Return value:
            None.
    */
    const changeDbButton = document.getElementById("changedb_button");
    const icon = document.createElement("i");
    icon.className = "fa fa-database";
    changeDbButton.replaceChildren(icon, document.createTextNode(` ${name}`));
}

function fetchDataDB() {
    fetch("/info", {
        method: "GET",
        headers: headers2
    }).then(response => response.json())
        .then(data => {
            setChangeDbButtonLabel(data['name']);
        });
}

function initPage() {
    initializeWidgetsAndListeners();
    fetchDataDB();
    fetchDetailedInfo();
}
$(document).ready(function () {
    initPage();
});
