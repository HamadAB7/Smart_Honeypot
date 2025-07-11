# Import library dependencies
from dash import Dash, html, dash_table, dcc
import dash_bootstrap_components as dbc
import plotly.express as px
from dash_bootstrap_templates import load_figure_template
from pathlib import Path
from dotenv import load_dotenv
import os
import pandas as pd

# Import project file
from dashboard_data_parser import *

# Constants
base_dir = Path(__file__).parent.parent
creds_audits_log_local_file_path = base_dir / 'smart_honeypot_proj' / 'log_files' / 'creds_audits.log'
cmd_audits_log_local_file_path = base_dir / 'smart_honeypot_proj' / 'log_files' / 'cmd_audits.log'

# Load environment vars
dotenv_path = Path('public.env')
load_dotenv(dotenv_path=dotenv_path)

# Load and parse data
creds_audits_log_df = parse_creds_audits_log(creds_audits_log_local_file_path)
cmd_audits_log_df = parse_cmd_audits_log(cmd_audits_log_local_file_path)

# Top 10 analytics
top_ip_address = top_10_calculator(creds_audits_log_df, "ip_address")
top_usernames = top_10_calculator(creds_audits_log_df, "username")
top_passwords = top_10_calculator(creds_audits_log_df, "password")
top_cmds = top_10_calculator(cmd_audits_log_df, "Command")

# Theme
load_figure_template(["cyborg"])
dbc_css = ("https://cdn.jsdelivr.net/gh/AnnMarieW/dash-bootstrap-templates@V1.0.4/dbc.min.css")

# Logo
image = 'assets/images/honeypy-logo-white.png'

# Declare Dash App
app = Dash(__name__, external_stylesheets=[dbc.themes.CYBORG, dbc_css])
app.title = "HONEYPY"
app._favicon = "../assets/images/honeypy-favicon.ico"

# ========== HEATMAP ==========

# Parse timestamp into datetime (assumes timestamp is in 'timestamp' column)
creds_audits_log_df['timestamp'] = pd.to_datetime(creds_audits_log_df['timestamp'])
creds_audits_log_df['hour'] = creds_audits_log_df['timestamp'].dt.hour
creds_audits_log_df['day'] = creds_audits_log_df['timestamp'].dt.day_name()

# Pivot login attempts into heatmap matrix
heatmap_data = creds_audits_log_df.groupby(['day', 'hour']).size().reset_index(name='attempts')
pivot_table = heatmap_data.pivot(index='day', columns='hour', values='attempts').fillna(0)

# Generate the heatmap
heatmap_fig = px.imshow(
    pivot_table,
    labels=dict(x="Hour of Day", y="Day of Week", color="Login Attempts"),
    x=pivot_table.columns,
    y=pivot_table.index,
    color_continuous_scale='Blues'
)
heatmap_fig.update_layout(title="Login Attempt Heatmap", height=400)

# ========== TABLES ==========
tables = html.Div([
    dbc.Row([
        dbc.Col(dash_table.DataTable(
            data=creds_audits_log_df.to_dict('records'),
            columns=[{"name": "IP Address", 'id': 'ip_address'}],
            style_table={'width': '100%', 'color': 'black'},
            style_cell={'textAlign': 'left', 'color': '#2a9fd6'},
            style_header={'fontWeight': 'bold'},
            page_size=10
        )),
        dbc.Col(dash_table.DataTable(
            data=creds_audits_log_df.to_dict('records'),
            columns=[{"name": "Usernames", 'id': 'username'}],
            style_table={'width': '100%'},
            style_cell={'textAlign': 'left', 'color': '#2a9fd6'},
            style_header={'fontWeight': 'bold'},
            page_size=10
        )),
        dbc.Col(dash_table.DataTable(
            data=creds_audits_log_df.to_dict('records'),
            columns=[{"name": "Passwords", 'id': 'password'}],
            style_table={'width': '100%','justifyContent': 'center'},
            style_cell={'textAlign': 'left', 'color': '#2a9fd6'},
            style_header={'fontWeight': 'bold'},
            page_size=10
        )),
    ])
])
apply_table_theme = html.Div([tables], className="dbc")

# ========== APP LAYOUT ==========
app.layout = dbc.Container([
    html.Div([html.Img(src=image, style={'height': '25%', 'width': '25%'})], style={'textAlign': 'center'}, className='dbc'),

    dbc.Row([
        dbc.Col(dcc.Graph(figure=px.bar(top_ip_address, x="ip_address", y='count')), width=4),
        dbc.Col(dcc.Graph(figure=px.bar(top_usernames, x='username', y='count')), width=4),
        dbc.Col(dcc.Graph(figure=px.bar(top_passwords, x='password', y='count'))),
    ], align='center', class_name='mb-4'),

    dbc.Row([
        dbc.Col(dcc.Graph(figure=px.bar(top_cmds, x='Command', y='count')), width=6),
        dbc.Col(dcc.Graph(figure=heatmap_fig), width=6)
    ], align='center', class_name='mb-4'),

    html.Div([
        html.H3("Intelligence Data", style={'textAlign': 'center', "font-family": 'Consolas, sans-serif', 'font-weight': 'bold'}),
    ]),
    
    apply_table_theme
])

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")
 