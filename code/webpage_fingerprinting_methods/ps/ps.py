from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction import DictVectorizer
from collections import Counter
from multiprocessing import Pool
import json
import os

class PS():
    @classmethod
    def get_name(cls):
        return "PS"
    
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
            
    def classify(self, train_visit_files, test_visit_files, visit_file_label, output_dir, n_cpu):
        train_x = self.get_x_all(train_visit_files, n_cpu)
        train_y = list([visit_file_label[x] for x in train_visit_files])
        
        test_x = self.get_x_all(test_visit_files, n_cpu)
        test_y = list([visit_file_label[x] for x in test_visit_files])

        classifier = Pipeline([
            ('vectorize', DictVectorizer()),
            ("classify", RandomForestClassifier(n_jobs=n_cpu, n_estimators=1000))
        ])
        classifier.fit(train_x, train_y)
        score = classifier.score(test_x, test_y)
        return score