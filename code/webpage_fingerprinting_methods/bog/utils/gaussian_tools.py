import itertools
import numpy as np
import os
import random
import re
import multiprocessing
from multiprocessing import Pool
import time

# CODE RELATED TO FITTING AND STORING GAUSSIANS

def load_clusters(training_file, assignment_file):
    clusters = {}
    handle_training = open(training_file)
    handle_assignments = open(assignment_file)
    for (points, cluster) in zip(handle_training, handle_assignments):
        points = re.match('.*1:(\d+) 2:(\d+).*', points).groups()
        points = np.array(list(map(float, points))).reshape(1,2)
        cluster = cluster.split()[0]
        if cluster not in clusters:
            clusters[cluster] = points
        else:
            clusters[cluster] = np.vstack([clusters[cluster], points])
    handle_training.close()
    handle_assignments.close()
    return clusters

def calc_mean(points):
    return np.mean(points, axis = 0)

def calc_covar(points):
    mean = calc_mean(points)
    tmp = np.array([1.0, 0.0, 0.0, 1.0]).reshape(2,2)
    for p in points:
        p -= mean
        col = p.reshape(2,1)
        row = p.reshape(1,2)
        tmp += np.dot(col, row)
    return tmp / (len(points) + 1)

def generate_gaussians(training_file, assignment_file, gaussian_file):
#     print('Generating Gaussians: %s' % gaussian_file)
    clusters = load_clusters(training_file, assignment_file)
    handle = open(gaussian_file, 'w')
    for cluster in clusters:
        mean = calc_mean(clusters[cluster])
        covar = calc_covar(clusters[cluster])
        handle.write('%s\t%s\t%s\t%s\t%s\t%s\n' % (mean[0], mean[1], covar[0,0], covar[0,1], covar[1,0], covar[1,1]))
    handle.close()
    
# CODE RELATED TO FEATURE EXTRACTION

def single_round(points, range_data, gaussian, num_samples):
#     print('single_round: %s' % os.getpid())
    coef, mean, covarinv = gaussian
    adjusted = points - mean
    likelihoods = coef * np.exp(-.5 * np.einsum('ij,ij->i', np.dot(adjusted, covarinv), adjusted))
    scores = np.zeros(num_samples)
    for (idx, start, end) in range_data:
        scores[idx] = likelihoods[np.arange(start, end)].sum()
    return scores / scores.max()
    
def get_gaussian_features(num_samples, pool, jobs):
    args = []
    for (points, range_data, gaussians) in jobs:
        args.append([(points, range_data, gaussian, num_samples) for gaussian in gaussians])
    args = list(itertools.chain(*args))
    all_features = pool.starmap(single_round, args, 50)
    all_features = np.column_stack(all_features)
    return all_features