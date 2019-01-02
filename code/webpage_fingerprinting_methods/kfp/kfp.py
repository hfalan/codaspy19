from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction import DictVectorizer
from collections import Counter
import pickle
from multiprocessing import Pool
import json
from . import RF_fextract_fixed_length
import os
class KFP():
    @classmethod
    def get_name(cls):
        return "KFP"
    
    def get_x(self, visit_file):
        with open(visit_file) as f:
            visit = json.load(f)
        packet_timestamp_size_list = []
        for connection in visit['tcp_connections']:
            for packet in connection['packets']:
                packet_timestamp_size_list.append((packet[0], packet[1]))
        packet_timestamp_size_list.sort(key=lambda x: x[0])
        first_packet_timestamp = packet_timestamp_size_list[0][0]
        packet_timestamp_size_list = [(x[0]-first_packet_timestamp, x[1]) for x in packet_timestamp_size_list]
        trace_data = ["{} {}".format(x[0], x[1]) for x in packet_timestamp_size_list]
        try:
            features = RF_fextract_fixed_length.TOTAL_FEATURES(trace_data)
        except Exception as e:
            print(e)
            features = [0]*175
        return features
            
    def get_x_all(self, visit_files, n_cpu):
        with Pool(n_cpu) as pool:
            return list(pool.map(self.get_x, visit_files))
            
    def classify(self, train_visit_files, test_visit_files, visit_file_label, output_dir, n_cpu):
        train_x = self.get_x_all(train_visit_files, n_cpu)
        train_y = list([visit_file_label[x] for x in train_visit_files])
        
        test_x = self.get_x_all(test_visit_files, n_cpu)
        test_y = list([visit_file_label[x] for x in test_visit_files])

        pipeline = Pipeline([
            ("classify", RandomForestClassifier(n_jobs=n_cpu, n_estimators=1000))
        ])
        pipeline.fit(train_x, train_y)
        score = pipeline.score(test_x, test_y)
        return score