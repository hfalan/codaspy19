from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction import DictVectorizer
from collections import Counter
import pickle
from multiprocessing import Pool
import json
import os, sys
cur_dir = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(cur_dir,"utils"))
from itertools import repeat
import attack
from collections import defaultdict
from collections import defaultdict, Counter
from sklearn.feature_extraction import DictVectorizer
import scipy.sparse
from multiprocessing import Pool
import numpy as np

def get_server_ip(tcp_connection_id, host_ip):
    server_ip = None
    for socket in tcp_connection_id.split("-"):
        ip = socket.split(":")[0]
        if ip != host_ip:
            server_ip = ip
            break
    return server_ip

def get_burst_pairs(packet_size_sequence):
    direction = -1
    burst_pairs = []
    outgoing = 0
    incoming = 0
    for size in packet_size_sequence:
        if size < 0 and direction == 1:
            burst_pairs.append((outgoing, incoming))
            outgoing = 0
            incoming = 0
            direction = -1
        if size > 0 and direction == -1:
            direction = 1
        if size < 0:
            outgoing += -1*size
        else:
            incoming += size
    burst_pairs.append((outgoing, incoming))

    return burst_pairs

def extract_features(visit):
    host_burst_pairs = defaultdict(list)
    packet_size_counter = Counter()

#     host_ip = raw_visit_data['host_ip']
    for connection in visit['tcp_connections']:
        server_ip = get_server_ip(connection['connection_id'], visit['visit_log']['host_ip'])
        server_host_name = visit['ip_to_name'].get(server_ip)
        packet_size_sequence = []
        for packet in connection['packets']:
            tcp_len = packet[1]
            if not tcp_len: continue
            packet_size_sequence.append(packet[1])
            packet_size_counter[packet[1]] += 1
            
        burst_pairs = get_burst_pairs(packet_size_sequence)
        host_burst_pairs[server_host_name] += burst_pairs  

    visit_features = {
                "host_burst_pairs" : host_burst_pairs,
                "packet_size_counter": packet_size_counter
            }
    return visit_features

def load_json(file_path):
    with open(file_path) as f:
        return json.load(f)
    
def load_visit(visit_file):
    visit = load_json(visit_file)
    return extract_features(visit)
    
def load_visit_features(visit_files, n_cpu):
    with Pool(n_cpu) as pool:
        visit_data = dict(zip(visit_files, pool.map(load_visit, visit_files)))     
    return visit_data

class BoG():
    @classmethod
    def get_name(cls):
        return "BoG"
    
    def get_x(self, visit_file):
        with open(visit_file) as f:
            visit = json.load(f)
        packet_sizes = []
        for connection in visit['tcp_connections']:
            packet_sizes += [x[1] for x in connection['packets']]
        return Counter(packet_sizes)
    
    def get_x_all(self, visit_files, n_cpu):
        with Pool(n_cpu) as pool:
            return list(pool.map(self.get_x, visit_files))
        
    def load_raw_data(self, training_visits, test_visits, visit_label, output_dir):
        ret = self.get_train_test_hold_lists(training_visits, test_visits, visit_label)
        train_list, test_list, hold_list = ret
        
        TRAINING_DIR = os.path.join(output_dir, 'training_points')
        TESTING_DIR = os.path.join(output_dir, 'testing_points')
        HOLDOUT_DIR = os.path.join(output_dir, 'holdout_points')
        DOMAIN_DIR = os.path.join(output_dir, 'domain_models')
        
        self.extract_points(train_list, TRAINING_DIR)
        self.extract_points(test_list, TESTING_DIR)
        self.extract_points(hold_list, HOLDOUT_DIR)
        
        # remove extraneous domains
        for d in set(os.listdir(TRAINING_DIR)).difference(set(os.listdir(TESTING_DIR))):
            os.remove(os.path.join(TRAINING_DIR, d))
        for d in set(os.listdir(TESTING_DIR)).difference(set(os.listdir(TRAINING_DIR))):
            os.remove(os.path.join(TESTING_DIR, d))
        tmp = set(os.listdir(TESTING_DIR)).union(set(os.listdir(TRAINING_DIR)))
        for d in set(os.listdir(HOLDOUT_DIR)).difference(tmp):
            os.remove(os.path.join(HOLDOUT_DIR, d))
        
        domains = []
        for d in os.listdir(TRAINING_DIR):
            domain = attack.Domain(DOMAIN_DIR, d, TRAINING_DIR, TESTING_DIR, HOLDOUT_DIR)
            domain.load_training_data()
            domains.append(domain) 
            

        
        return domains, train_list, test_list, hold_list
            
    def classify(self, train_visit_files, test_visit_files, visit_file_label, output_dir, n_cpu):
        training_visit_data = load_visit_features(train_visit_files, n_cpu)
        test_visit_data = load_visit_features(test_visit_files, n_cpu)
        self.visit_features = {**training_visit_data, **test_visit_data}
        labels = set(visit_file_label.values())
        label_to_id = dict(zip(labels, range(len(labels))))
        visit_label_id = {visit:label_to_id[label] for visit,label in visit_file_label.items()}
        ret_val = self.load_raw_data(train_visit_files, test_visit_files, visit_label_id, output_dir)
        domains, train_list, test_list, hold_list = ret_val
        
        packet_size_features = self.get_packet_size_features(train_list, test_list, hold_list)
        
        attack.main(domains, train_list, test_list, hold_list, packet_size_features, output_dir, n_cpu)
        
        with open(os.path.join(output_dir, "lr_accuracy")) as f:
            return float(f.readlines()[0].split()[-1])
#         train_x = self.get_x_all(train_visit_files, n_cpu)
#         train_y = list([visit_file_label[x] for x in train_visit_files])
        
#         test_x = self.get_x_all(test_visit_files, n_cpu)
#         test_y = list([visit_file_label[x] for x in test_visit_files])

#         classifier = Pipeline([
#             ('vectorize', DictVectorizer()),
#             ("classify", RandomForestClassifier(n_jobs=n_cpu, n_estimators=600))
#         ])
#         classifier.fit(train_x, train_y)
#         score = classifier.score(test_x, test_y)


    @classmethod
    def get_server_ip(cls, tcp_connection_id, host_ip):
        server_ip = None
        for socket in tcp_connection_id.split("-"):
            ip = socket.split(":")[0]
            if ip != host_ip:
                server_ip = ip
                break
        return server_ip
    
    @classmethod
    def get_train_test_hold_lists(cls, training_visits, test_visits, visit_label):
        #Miller et al. use train, test, holdout terminology
        #be consistent, split training_visits and crate a test dataset that will be used for validation
        
        label_visits = defaultdict(list)
        for visit_id in training_visits:
            label = visit_label[visit_id]
            label_visits[label].append((visit_id, label))
    
        #determine train and test 
        #split training_visits to half
        train_list = []
        test_list = []
        hold_list = []
        for label, visits in label_visits.items():
            sorted_visits = sorted(visits)
            split_index = len(visits)//2 #use half of the training samples for validation
            train_list += sorted_visits[:split_index] #first half
            test_list += sorted_visits[split_index:]
            
        for visit_id in test_visits: 
            label = visit_label[visit_id]
            hold_list.append((visit_id, label))
        return train_list, test_list, hold_list
    
    def extract_points(self, sample_list, out_dir):
        os.makedirs(out_dir, exist_ok=True)
        data_points = self.load_all_sample_points(sample_list)
        self.write_point_files(data_points, out_dir)
        
    def load_all_sample_points(self, sample_list):
        
#         print(self.visit_data[list(self.visit_data)[0]])
        #pets2014_miller_code/code/bog/extract_points.py 
        #load_all_sample_points(sample_list, feature_db)
        data_points = defaultdict(list)
        for sample in sample_list:
            visit_id = sample[0]
            
            visit_features = self.visit_features[visit_id]
            for host, burst_pairs in visit_features['host_burst_pairs'].items():
                for burst_pair in burst_pairs:
                    point = [burst_pair[0], burst_pair[1], sample[0], sample[1]]
                    data_points[self.get_second_level_domain(host)].append(point)
        return data_points
        
    @classmethod
    def write_point_files(self, data_points, out_dir):
        #pets2014_miller_code/code/bog/extract_points.py
        #def extract_points(feature_db, out_dir, name_file, sample_key_file, all_points = False, max_points = None):
        #an example line from a point file:
        #https://www.bankofamerica.com/deposits/savings/savings-accounts/ 1:198 2:3061 # 2017-11-15-12-51-12-616030.0
        for domain, points in data_points.items():
            with open(os.path.join(out_dir, domain), 'w') as f:
                for (outgoing, incoming, sample_name, label) in points:
                    f.write('%s 1:%s 2:%s # %s\n' % (label, outgoing, incoming, sample_name))

    @classmethod
    def get_second_level_domain(self, host):
        #pets2014_miller_code/code/feature_extractor.py
        #def getHost(ip)
        if not host:
            return "unknown"
        
        tld_idx = host.rfind('.')
        domain_idx = host.rfind('.', 0, tld_idx)
        if domain_idx != -1:
            host = host[(domain_idx + 1):]
        return host
    
    def get_packet_size_counter_list(self, sample_list):
        packet_size_counter_list = []
        for sample in sample_list:
            visit_id = sample[0]
            
            visit_features = self.visit_features[visit_id]
            packet_size_counter = visit_features['packet_size_counter']
            packet_size_counter_list.append(packet_size_counter)
        return packet_size_counter_list
    
    def get_packet_size_features(self, train_list, test_list, hold_list):
        train_counters = self.get_packet_size_counter_list(train_list)
        test_counters = self.get_packet_size_counter_list(test_list)
        hold_counters = self.get_packet_size_counter_list(hold_list)
        
        train_counters = train_counters + test_counters 
        v = DictVectorizer()
        train_packet_size_features = v.fit_transform(train_counters)
        test_packet_size_features = v.transform(hold_counters)
        packet_size_features = np.row_stack([train_packet_size_features.todense(), test_packet_size_features.todense()])
        rows, cols = packet_size_features.shape
#         print(rows, len(train_list) + len(test_list) + len(hold_list))
        assert rows == len(train_list) + len(test_list) + len(hold_list)
        for i in range(cols):  # normalize
            packet_size_features[:,i] = packet_size_features[:,i] / packet_size_features[:,i].max()
        packet_size_features = scipy.sparse.csr_matrix(packet_size_features)
        return packet_size_features