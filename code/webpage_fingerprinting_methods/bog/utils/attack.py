import os
import re
import numpy as np
from multiprocessing import Pool
import itertools
from commands import *
from gaussian_tools import generate_gaussians, get_gaussian_features
import scipy.sparse

class Domain(object):

    def __init__(self, domain_dir, domain_name, training_dir, testing_dir, holdout_dir):
        self.domain_name = domain_name
        self.domain_root = os.path.join(domain_dir, domain_name)
        if not os.path.exists(self.domain_root):
            os.makedirs(self.domain_root)
        self.training_points = os.path.join(training_dir, domain_name)
        self.testing_points = os.path.join(testing_dir, domain_name)
        self.holdout_points = os.path.join(holdout_dir, domain_name)

    def __str__(self):
        return self.domain_name

    def _get_centroids(self, job):
        return os.path.join(self.domain_root, job, 'centroids')

    def _get_assignments(self, job):
        return os.path.join(self.domain_root, job, 'assignments')

    def _get_gaussians(self, job):
        return os.path.join(self.domain_root, job, 'gaussians')

    def _get_training_file(self, job):
        return os.path.join(self.domain_root, job, 'training_features')

    def _get_testing_file(self, job):
        return os.path.join(self.domain_root, job, 'testing_features')

    def _get_model_file(self, job):
        return os.path.join(self.domain_root, job, 'model')

    def _get_prediction_file(self, job):
        return os.path.join(self.domain_root, job, 'prediction')

    def _get_accuracy_file(self, job):
        return os.path.join(self.domain_root, job, 'lr_accuracy')

    def load_training_data(self):
        handle = open(self.training_points)
        self.num_training_points = len(handle.read().strip().split('\n'))
        handle.close()

    def get_kmeans_jobs(self):
        kmeans_jobs = []
        k_range = list(filter(lambda x: x < self.num_training_points / 3, [4000, 1000, 500]))
        if len(k_range) < 3:
            k_range = [max(1, self.num_training_points / 3)] + k_range
        for k in k_range:
            for init in ['random']:
                for batch_size in [100]:
                    for iterations in [500]:
                        dir_name = 'k_%s__in_%s__b_%s__it_%s' % (k, init, batch_size, iterations)
                        kmeans_dir = os.path.join(self.domain_root, dir_name)
                        if not os.path.exists(kmeans_dir):
                            os.makedirs(kmeans_dir)
                        kmeans_jobs.append((self._get_centroids(dir_name), self.training_points,
                                            k, init, batch_size, iterations))
        return kmeans_jobs

    def get_assignment_jobs(self):
        jobs = os.listdir(self.domain_root)
        jobs = [j for j in jobs if re.match('k_.*', j)]
        assignment_jobs = []
        for j in jobs:
            assignment_jobs.append((self.training_points, self._get_centroids(j), self._get_assignments(j)))
        return assignment_jobs
                                   
    def get_gaussian_jobs(self):
        jobs = os.listdir(self.domain_root)
        jobs = [j for j in jobs if re.match('k_.*', j)]
        gaussian_jobs = []
        for j in jobs:
            gaussian_jobs.append((self.training_points, self._get_assignments(j), self._get_gaussians(j)))
        return gaussian_jobs

    def _load_gaussians(self, gaussian_file):
        gaussians = []
        handle = open(gaussian_file)
        for line in handle:
            mean_0, mean_1, covar_0, covar_1, covar_2, covar_3 = [float(t) for t in line.split()]
            mean = np.array([mean_0, mean_1])
            covar = np.array([covar_0, covar_1, covar_2, covar_3]).reshape(2,2)
            coef = ((2.0 * np.pi) ** -1.0) * (np.linalg.det(covar) ** -.5)
            covarinv = np.linalg.inv(covar)
            gaussians.append((coef, mean, covarinv))
        handle.close()
        return gaussians
        
    def get_cluster_sets(self):
#         print('Getting Cluster Sets: %s' % self.domain_name)
        jobs = os.listdir(self.domain_root)
        jobs = [j for j in jobs if re.match('k_.*', j)]
        feature_jobs = []
        for j in jobs:
            gaussians = self._load_gaussians(self._get_gaussians(j))
            feature_jobs.append((gaussians, self._get_training_file(j), self._get_testing_file(j)))
        return feature_jobs

    def _load_points(self, point_file):
        point_dict = {}  # sample :-> [points]
        label_dict = {}  # sample :-> label
        if not os.path.exists(point_file):
            return (point_dict, label_dict.items())
        handle = open(point_file)
        for line in handle:
#             label, x, y, sample_name = re.match('([0-9-]+) 1:(\d+) 2:(\d+) # ([a-z0-9_.-]+)', line).groups()
            label, x, y, sample_name = re.match('([0-9-]+) 1:(\d+) 2:(\d+) # (.+)', line).groups()
            if sample_name not in point_dict:
                point_dict[sample_name] = []
            point_dict[sample_name].append(np.array([int(x), int(y)]))
            label_dict[sample_name] = label
        handle.close()
        return (point_dict, label_dict.items())
            
    def get_points(self, sample_orders = None):
#         print('Getting Points: %s' % self.domain_name)
        # load points
        if not sample_orders:
            train_points, train_sample_labels = self._load_points(self.training_points)
            test_points, test_sample_labels = self._load_points(self.testing_points)
        else:
            train_points, _ = self._load_points(self.training_points)
            tmp_points, _ = self._load_points(self.testing_points)
            train_points.update(tmp_points)
            test_points, _ = self._load_points(self.holdout_points)
            train_sample_labels, test_sample_labels = sample_orders
        # populate points and range_data
        points = []
        range_data = []
        for (idx, (sample, _)) in enumerate(train_sample_labels):
            if sample in train_points:
                sample_points = train_points[sample]
                range_data.append((idx, len(points), len(points) + len(sample_points)))
                points.extend(sample_points)
        cutoff = len(train_sample_labels)
        for (idx, (sample, _)) in enumerate(test_sample_labels):
            if sample in test_points:
                sample_points = test_points[sample]
                range_data.append((idx + cutoff, len(points), len(points) + len(sample_points)))
                points.extend(sample_points)
        # return final values
        return (points, range_data, list(train_sample_labels), list(test_sample_labels))

    def get_train_jobs(self):
        jobs = os.listdir(self.domain_root)
        jobs = [j for j in jobs if re.match('k_.*', j)]
        train_jobs = []
        for j in jobs:
            train_jobs.append((self._get_training_file(j), self._get_model_file(j)))
        return train_jobs

    def get_predict_jobs(self):
        jobs = os.listdir(self.domain_root)
        jobs = [j for j in jobs if re.match('k_.*', j)]
        predict_jobs = []
        for j in jobs:
            predict_jobs.append((self._get_testing_file(j), self._get_model_file(j),
                                 self._get_prediction_file(j), self._get_accuracy_file(j)))
        return predict_jobs

    def get_best_gaussians(self):
        jobs = os.listdir(self.domain_root)
        jobs = [j for j in jobs if re.match('k_.*', j)]
        best_accuracy = None
        for j in jobs:
            handle = open(self._get_accuracy_file(j))
            accuracy = float(handle.read().strip().split('\n')[0].split(':')[1])
            handle.close()
            if best_accuracy == None or accuracy > best_accuracy:
                best_accuracy = accuracy
                best_gaussians = self._load_gaussians(self._get_gaussians(j))
        return best_gaussians
    
    
def write_features(train_file, test_file, train_sample_labels, test_sample_labels, all_features, sparse):
    def helper(path, features, sample_labels, sparse):
        handle = open(path, 'w')
        assert features.shape[0] == len(sample_labels)
        for i in range(len(sample_labels)):
            sample_features = features[i, :]
            if sparse:
                sample_features = sample_features.toarray()[0]
            sample_name, sample_label = sample_labels[i]
            handle.write('%s ' % sample_label)
            for idx, value in enumerate(sample_features):
                if value > .0000000001:
                    handle.write('%d:%.10f ' % (idx + 1, value))
            handle.write('# %s\n' % sample_name)
        handle.close()
    num_samples = len(train_sample_labels) + len(test_sample_labels)
    assert all_features.shape[0] == num_samples
    training_features = all_features[np.arange(len(train_sample_labels)), :]
    testing_features = all_features[np.arange(len(train_sample_labels), num_samples), :]
    helper(train_file, training_features, train_sample_labels, sparse)
    helper(test_file, testing_features, test_sample_labels, sparse)
    
    
def main(domains, train_list, test_list, hold_list, packet_size_features, output_dir, n_cpu):
    
    pool = Pool(n_cpu)
    
#     extract centroids
    kmeans_jobs = itertools.chain(*[d.get_kmeans_jobs() for d in domains])
    pool.starmap(extract_centroids, kmeans_jobs)
    # generate assignments
    assignment_jobs = itertools.chain(*[d.get_assignment_jobs() for d in domains])
    pool.starmap(generate_assignments, assignment_jobs)
    # generate gaussians
    gaussian_jobs = itertools.chain(*[d.get_gaussian_jobs() for d in domains])
    pool.starmap(generate_gaussians, gaussian_jobs)
    
    # generate features
    all_points = [d.get_points() for d in domains]
    all_cluster_sets = [d.get_cluster_sets() for d in domains]
    for (points, clusters, domain) in zip(all_points, all_cluster_sets, domains):
#         print('Processing: %s' % domain)
        point_matrix, range_data, train_sample_labels, test_sample_labels = points
        num_samples = len(train_sample_labels) + len(test_sample_labels)
        for (gaussians, train_file, test_file) in clusters:
            all_features = get_gaussian_features(num_samples, pool, [(point_matrix, range_data, gaussians)])
            write_features(train_file, test_file, train_sample_labels, test_sample_labels, all_features, False)
            
    # train models
    train_jobs = itertools.chain(*[d.get_train_jobs() for d in domains])
    pool.starmap(train_model, train_jobs)
    
    # run predict
    predict_jobs = itertools.chain(*[d.get_predict_jobs() for d in domains])
    pool.starmap(predict, predict_jobs)
    
    
    # generate features using best sets of gaussians
    sample_orders = (train_list + test_list, hold_list)
    all_points = [d.get_points(sample_orders = sample_orders) for d in domains]
    best_gaussians = [d.get_best_gaussians() for d in domains]
    jobs = []
    for (points, gaussians, domain) in zip(all_points, best_gaussians, domains):
        point_matrix, range_data, _, _ = list(points)        
        jobs.append((point_matrix, range_data, gaussians))
        
    burst_pair_features = get_gaussian_features(len(train_list) + len(test_list) + len(hold_list), pool, jobs)
    burst_pair_features = scipy.sparse.csr_matrix(burst_pair_features)
    
    all_features = scipy.sparse.hstack([packet_size_features, burst_pair_features], format = 'csr')
#     all_features = packet_size_features
#     all_features = burst_pair_features
    TRAINING_FEATURES = os.path.join(output_dir, 'training_features')
    HOLDOUT_FEATURES = os.path.join(output_dir, 'holdout_features')
    write_features(TRAINING_FEATURES, HOLDOUT_FEATURES, train_list + test_list, hold_list, all_features, True)
    # train composite model
    MODEL = os.path.join(output_dir, 'model')
    train_model(TRAINING_FEATURES, MODEL, args = '-s 7 -c 128')
    # do final prediction
    PREDICT = os.path.join(output_dir, 'predict')
    predict(HOLDOUT_FEATURES, MODEL, PREDICT, os.path.join(output_dir, 'lr_accuracy'), args = '-b 1')