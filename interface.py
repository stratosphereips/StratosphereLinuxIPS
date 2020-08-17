# Run this app with `python app.py` and
# visit http://127.0.0.1:8050/ in your web browser.

import dash
from dash.dependencies import Input, Output
import dash_table
import dash_core_components as dcc
import dash_html_components as html
import redis
import json
external_stylesheets = ['https://codepen.io/chriddyp/pen/bWLwgP.css']
r = redis.StrictRedis(host='localhost', port=6379, db=0, charset="utf-8", decode_responses=True) #password='password')
all_keys = r.keys('*')
#tree_IPs = [ for key in all_keys]
tws_list = [json.loads(line) for line in r.zrange("profile_10.8.0.69_timewindow4_timeline",0,-1)]
app = dash.Dash(__name__, external_stylesheets=external_stylesheets)
app.layout = html.Div(
    [dash_table.DataTable(
        id = 'datatable-interactivity',
        columns = [
            {"name": i, "id": i, "deletable": True, "selectable":True} for i in tws_list[0].keys()
        ],
        data = tws_list,
        editable = True,
        filter_action = "native",
        sort_action = "native",
        sort_mode = "multi",
        column_selectable = "single",
        row_selectable = "multi",
        row_deletable = True,
        selected_columns = [],
        selected_rows = [],
        page_action = "native",
        page_current = 0,
        page_size = 10,
    ),
    html.Listing(
        id = 'tree-list',
        title = 'TREE LIST',
        #data =[{'sdcs': ['sadsa','ferfef']}, {'qwqw':['qwqw','werewr']}] )
        children = ['sdfds','sdfdsfdsf','qqw']
        )
])

@app.callback(
    Output('datatable-interactivity', "style_data_conditional"),
    [Input('datatable-interactivity', "selected_columns")]
)
def update_styles(selected_columns):
    return [{
        'if': {'column_id': i},
        'background_color': '#D2F3FF'
        } for i in selected_columns]

if __name__ == '__main__':
    app.run_server(debug=True)

