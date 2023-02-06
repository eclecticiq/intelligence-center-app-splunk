"use strict";

const appName = "TA-eclecticiq";
const appNamespace = {
    owner: "nobody",
    app: appName,
    sharing: "app",
};
const pwRealm = "TA-eclecticiq_realm";


// Splunk Web Framework Provided files
require([
    "underscore", "jquery", "splunkjs/splunk", "splunkjs/mvc",
], function (_, $, splunk_js_sdk, mvc) {
    console.log("start")
    console.log("lookup_observables.js require(...) called");
    tokens = mvc.Components.get("default");
    var value = tokens.get("q")
    var index = tokens.get("index")
    var host = tokens.get("host")
    var source = tokens.get("source")
    var sourcetype = tokens.get("sourcetype")
    var event_time = tokens.get("event_time")
    var field_name = tokens.get("field_name")
    $("#msg").css('color', 'blue');
    $("#loading").text("Loading...")
    console.log("initializing service")
    var http = new splunk_js_sdk.SplunkWebHttp();
    console.log("http initialized")
    var service = new splunkjs.Service(
        http,
        appNamespace,
    );
    console.log("service initialized! getting storage passwords")

    data = {}
    data['value'] = value

    completeSetup(data)
    sighting_url = "create_sighting_dashboard?q=" + value
    sighting_url = sighting_url + "&index=" + index + "&"
    sighting_url = sighting_url + "&host=" + host + "&"
    sighting_url = sighting_url + "&source=" + source + "&"
    sighting_url = sighting_url + "&sourcetype=" + sourcetype + "&"
    sighting_url = sighting_url + "&event_time=" + event_time + "&"
    sighting_url = sighting_url + "&field_name=" + field_name

    $("#create_sighting").click(function () { window.location.replace(sighting_url); });

    async function makeRequest(url, data) {
        return new Promise((resolve, reject) => {
            const service = mvc.createService();
            service.post(url, data, (err, resp) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(resp);
                }
            })
        })
    }


    // function for "Lookup observables"
    async function completeSetup(data) {
        console.log("lookup_observables.js completeSetup called");

        try {
            response = makeRequest('/services/lookup_observables', data);

            await response;
        } catch (e) {
            console.log(e)

        }

        console.log("lookup_observables endpoint called.");


    }
    response.then(function (result) {
        console.log("Response Received.")
        $("#loading").text("")
        console.log(result['data'][0])
        if (result.data.length > 1) {
            $("#mytable").append(createTable(result['data'][0]))
        }
        else {
            $("#msg").css('color', 'black');
            $("#loading").text("No data found!")
        }
    }
    ).catch(function (error) {
        // log and rethrow 
        console.log(error);
        $("#msg").css('color', 'red');
        $("#loading").text(error["data"]);
        stop();
    });;

    function createTable(data) {

        var table_header = `<table class="table table-striped tableChart chart1Top"  style="width: 100%; color: black;  border: 1px solid #dddddd;
                            height: 30px;" id="chart1">
                                <thead>
                                    <tr role="row" style="background-color: #42b598 !important;">
                                        <th class="sorting_asc" tabindex="0" scope="col"
                                            rowspan="1" colspan="1" aria-sort="ascending"
                                             style="width: 700px; background-color: #42b598 !important;">
                                            Title</th>
                                        <th class="sorting_asc" tabindex="0" scope="col"
                                            rowspan="1" colspan="1" aria-sort="ascending"
                                             style="width: 700px; background-color: #42b598 !important;">
                                            Description</th>
                                             <th class="sorting_asc" tabindex="0" scope="col"
                                            rowspan="1" colspan="1" aria-sort="ascending"
                                             style="width: 700px; background-color: #42b598 !important;">

                                             Source Name</th>
                                             <th class="sorting_asc" tabindex="0" scope="col"
                                            rowspan="1" colspan="1" aria-sort="ascending"
                                             style="width: 700px; background-color: #42b598 !important;">

                                            Tags</th>
                                             <th class="sorting_asc" tabindex="0" scope="col"
                                            rowspan="1" colspan="1" aria-sort="ascending"
                                             style="width: 700px; background-color: #42b598 !important;">

                                             Threat Start</th>
                                             <th class="sorting_asc" tabindex="0" scope="col"
                                            rowspan="1" colspan="1" aria-sort="ascending"
                                             style="width: 700px; background-color: #42b598 !important;">


                                            Observables</th>
                                    </tr>
                                </thead> <tbody>`

        var tbody = ""
        for (item in data) {
            if (item < data.length - 1) {
                var str_htm = "<tr>"
                str_htm = str_htm + "<td>" + data[item]["title"] + "</td>"
                str_htm = str_htm + "<td>" + data[item]["description"] + "</td>"
                str_htm = str_htm + "<td>" + data[item]["source_name"] + "</td>"
                str_htm = str_htm + "<td>" + data[item]["tags"] + "</td>"
                str_htm = str_htm + "<td>" + data[item]["threat_start_time"] + "</td>"
                start = "<td><table  class=\"table table-striped tableChart chart1Top\"  style=\"width: 100%; color: black;  border: 1px solid #dddddd;height: 30px;\" id=\"chart\"><thead><th role=\"row\" style=\"background-color: #42b598;\">Kind</th><th role=\"row\" style=\"background-color: #42b598;\">Value</th><th role=\"row\" style=\"background-color: #42b598;\">Maliciousness</th></thead><tbody>"

                for (var item1 in data[item]['observables']) {
                    if (item1 < data[item]['observables'].length) {
                        start = start + "<tr><td>" + data[item]['observables'][item1]["type"] + "</td>" + "<td>" + data[item]['observables'][item1]["value"] + "</td>" + "<td>" + data[item]['observables'][item1]["classification"] + "</td></tr>"
                    }
                }

                start = start + "</tbody></table></td>"
                str_htm = str_htm + start
                tbody = tbody + str_htm + "</tr>"

            }

        }
        tbody = tbody + "</tbody>"
        table_header = table_header + tbody + "</table>"
        return table_header
    }


});




