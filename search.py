import os
import csv

path = '/media/yongyu/Data/ICS/siemens/build/tmp/work/i586-nlp-32-poky-linux'

with open("siemens-cve.csv", 'w') as f:
    wr = csv.writer(f)

    for package in os.listdir(path):
        version = os.listdir(path + '/' + package)[0]
        for file in os.listdir(path + '/' + package + '/' + version):
            if os.path.isfile(path + '/' + package + '/' + version + '/' + file):
                if 'CVE' in file:
                    print(package, file)
                    wr.writerow([package, version, file])
    