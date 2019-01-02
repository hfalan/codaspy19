import subprocess
import textwrap
import re
import os

# function for issuing command line commands
def issue_command(cmd):
#     print('\nIssuing: %s' % cmd)
    try:
        p0 = subprocess.Popen(cmd,
                              stdout = subprocess.PIPE,
                              stderr = subprocess.PIPE,
                              shell = True, encoding='utf8')
        (stdout, stderr) = p0.communicate()
    except Exception as e:
        print('Error occurred inovking command: %s' % cmd)
        raise e
    if p0.returncode == 0:
        lines = stdout.split('\n')
        lines = map(lambda l: textwrap.fill(l, 80, initial_indent = '> ', subsequent_indent = '>>> '), lines)
#         print('\nCommand Successful: %s\n%s' % (cmd, '\n'.join(lines)))
        return stdout, stderr
    else:
        lines = stderr.split('\n')
        lines = map(lambda l: textwrap.fill(l, 80, initial_indent = '> ', subsequent_indent = '>>> '), lines)
        msg = 'Command "%s" returned non-zero exit code: %s\n%s\n' % (cmd, p0.returncode, '\n'.join(lines))
        raise Exception(msg)
        
# invoke sofia-ml to extract centroids
def extract_centroids(out_file, training_file, k, init, batch_size, iterations):
    cmd = [os.path.expanduser("~/software/sofia-ml-master/cluster-src/sofia-kmeans"),
           '--dimensionality 3',
           '--k %d' % k,
           '--init_type %s' % init,
           '--opt_type mini_batch_kmeans',
           '--mini_batch_size %s' % batch_size,
           '--iterations %s' % iterations,
           '--training_file %s' % training_file,
           '--model_out %s' % out_file,
           '--objective_after_init',
           '--objective_after_training']
    issue_command('  '.join(cmd))
    
# given centroids, assign points into clusters
def generate_assignments(point_file, centroid_file, assignment_file):
    cmd = [os.path.expanduser("~/software/sofia-ml-master/cluster-src/sofia-kmeans"),
           '--test_file %s' % point_file,
           '--model_in %s' % centroid_file,
           '--cluster_assignments_out %s' % assignment_file,
           '--objective_on_test']
    issue_command('  '.join(cmd))
    
# train a model given a file of features
def train_model(training_features, model, args = ''):
    cmd = [os.path.expanduser("~/software/liblinear-2.20/train"),
           '-q',
           '%s' % args,
           training_features,
           model]
    issue_command('  '.join(cmd))

# make predictions given a model and feature file
def predict(testing_features, model, prediction_file, accuracy_file, args = ''):
    cmd = [os.path.expanduser("~/software/liblinear-2.20/predict"),
           '%s' % args,
           testing_features,
           model,
           prediction_file]
    stdout, _ = issue_command('  '.join(cmd))
    accuracy, correct, total = re.match('Accuracy = ([0-9.]+)% \((\d+)/(\d+)\)', stdout).groups()
    handle = open(accuracy_file, 'w')
    handle.write('accuracy: %s\ncorrect: %s\ntotal: %s\n' % (accuracy, correct, total))
    handle.close()