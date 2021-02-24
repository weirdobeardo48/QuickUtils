#!/usr/bin/python3
import sys
import subprocess
import os
import argparse
import os.path

args = argparse.ArgumentParser()
args.add_argument("--path",required=True, help="Path to image folder")
args = args.parse_args()

file_path = args.path


if __name__ == '__main__':
    # Check if path is a folder
    if os.path.isdir(file_path):
        print("Here is the file path: %s" % file_path)
        # Do something
        files = os.listdir(file_path)
        if len(files) > 0:
            # Get a random number
            import random as rand
            lucky_number = rand.randint(0 , len(files) - 1)
            print("Here is the lucky number: %s, %s" %(str(lucky_number), os.path.join(file_path, files[lucky_number])))
            bash_command = "cat %s" % os.path.join(file_path, files[lucky_number])
            bash_command_2 = "tee /etc/motd"
            p1 = subprocess.Popen(bash_command.split(), stdout=subprocess.PIPE)
            p2 = subprocess.Popen(bash_command_2.split(), stdin=p1.stdout, stdout=subprocess.PIPE)
            p2.communicate()
    else:
        sys.exit(1)
