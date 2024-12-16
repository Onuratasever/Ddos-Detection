import pandas as pd
from scapy.all import sniff
from datetime import datetime
from collections import defaultdict

protocol_map = {
    6: 'TCP',
    17: 'UDP',
    1: 'ICMP'
}

flows = defaultdict(lambda: {
    'dt': None,
    'switch': None,
    'src': None,
    'dst': None,
    'pktcount': 0,
    'bytecount': 0,
    'dur': None,
    'dur_nsec': None,
    'tot_dur': None,
    'flows': None,
    'packetins': None,
    'pktperflow': None,
    'byteperflow': None,
    'pktrate': None,
    'Pairflow': None,
    'Protocol': None,
    'port_no': None,
    'tx_bytes': 0,
    'rx_bytes': 0,
    'tx_kbps': None,
    'rx_kbps': None,
    'tot_kbps': None
})

# Paket işleme fonksiyonu
def process_packet(packet):
    if 'IP' in packet:
        flow_key = (packet['IP'].src, packet['IP'].dst, packet['IP'].proto)

        if flows[flow_key]['dt'] is None:
            flows[flow_key]['dt'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if flows[flow_key]['dur'] is None:
            flows[flow_key]['dur'] = datetime.now()
        flows[flow_key]['dur_nsec'] = datetime.now()

        # Akış bilgilerini güncelle
        flows[flow_key]['src'] = packet['IP'].src
        flows[flow_key]['dst'] = packet['IP'].dst
        flows[flow_key]['Protocol'] = protocol_map.get(packet['IP'].proto, 'Unknown')
        flows[flow_key]['pktcount'] += 1
        flows[flow_key]['bytecount'] += len(packet)
        flows[flow_key]['port_no'] = packet['IP'].fields.get('dport', None)

        flows[flow_key]['tx_bytes'] += len(packet)
        reverse_flow_key = (packet['IP'].dst, packet['IP'].src, packet['IP'].proto)
        flows[reverse_flow_key]['rx_bytes'] += len(packet)

# Ağ trafiğini yakala
sniff(prn=process_packet, count=5)

# Hesaplamalar
for flow_key, data in flows.items():
    if data['dt']:
        try:
            dt_obj = datetime.strptime(data['dt'], '%Y-%m-%d %H:%M:%S')
            data['dt'] = int(dt_obj.strftime('%Y%m%d%H%M%S'))
        except ValueError:
            data['dt'] = None

    if data['dur']:
        try:
            dur_obj = datetime.strptime(str(data['dur']), '%Y-%m-%d %H:%M:%S.%f')
            data['dur'] = int(dur_obj.strftime('%Y%m%d%H%M%S%f'))
        except ValueError:
            data['dur'] = None

    if data['dur_nsec']:
        try:
            dur_nsec_obj = datetime.strptime(str(data['dur_nsec']), '%Y-%m-%d %H:%M:%S.%f')
            data['dur_nsec'] = int(dur_nsec_obj.strftime('%Y%m%d%H%M%S%f'))
        except ValueError:
            data['dur_nsec'] = None
    
    # Byte per Flow ve Packet per Flow
    if data['pktcount'] > 0:
        data['byteperflow'] = data['bytecount'] / data['pktcount']
        data['pktperflow'] = data['pktcount']
    
    # Packet Rate
    if data['tot_dur'] and data['tot_dur'] > 0:
        data['pktrate'] = data['pktcount'] / data['tot_dur']
    
    # Transmission ve Reception Rates
    if data['tot_dur'] and data['tot_dur'] > 0:
        data['tx_kbps'] = (data['tx_bytes'] * 8) / (data['tot_dur'] * 1024)
        data['rx_kbps'] = (data['rx_bytes'] * 8) / (data['tot_dur'] * 1024)
        data['tot_kbps'] = data['tx_kbps'] + data['rx_kbps']

df = pd.DataFrame([
    {
        'dt': data['dt'],
        'switch': data['switch'],
        'src': data['src'],
        'dst': data['dst'],
        'pktcount': data['pktcount'],
        'bytecount': data['bytecount'],
        'dur': data['dur'],
        'dur_nsec': data['dur_nsec'],
        'tot_dur': data['tot_dur'],
        'flows': None,
        'packetins': data['packetins'],
        'pktperflow': data['pktperflow'],
        'byteperflow': data['byteperflow'],
        'pktrate': data['pktrate'],
        'Pairflow': None,
        'Protocol': data['Protocol'],
        'port_no': data['port_no'],
        'tx_bytes': data['tx_bytes'],
        'rx_bytes': data['rx_bytes'],
        'tx_kbps': data['tx_kbps'],
        'rx_kbps': data['rx_kbps'],
        'tot_kbps': data['tot_kbps']
    }
    for flow_key, data in flows.items()
])

# DataFrame'i göster
# print(df)
# df.to_csv('output.csv', index=False)
# df.fillna(0, inplace=True)
# df.to_csv('output2.csv', index=False)


from sklearn.preprocessing import MinMaxScaler
import pandas as pd

categorical_columns = ['src', 'dst', 'Protocol']
numerical_columns = [col for col in df.columns if col not in categorical_columns]

df[categorical_columns] = df[categorical_columns].fillna('Unknown')

df[numerical_columns] = df[numerical_columns].fillna(0)

import json

with open('train_columns.json', 'r') as f:
    train_columns = json.load(f)

if 'label' in train_columns:
    train_columns.remove('label')

df_encoded = pd.get_dummies(df, columns=categorical_columns, drop_first=True)

for col in train_columns:
    if col not in df_encoded.columns and col != "label":
        df_encoded[col] = 0  

df_encoded = df_encoded[train_columns]

scaler = MinMaxScaler()

x_scaled = scaler.fit_transform(df_encoded)

df_encoded.to_csv('output3.csv', index=False)
import joblib

voting_model = joblib.load('voting_model.joblib')

predictions = voting_model.predict(x_scaled)
print(predictions)

rf_clf = joblib.load('rf_clf.joblib')
predictions = rf_clf.predict(x_scaled)

print(predictions)